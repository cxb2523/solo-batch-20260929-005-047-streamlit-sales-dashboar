"""Sales dashboard with a self-contained login gate.

Auth design (see tests/test_auth_flow.py):
  * Credentials live in credentials.json next to this file. Paths are always
    resolved from __file__ so the app works regardless of the current working
    directory / how streamlit was launched.
  * Passwords are only ever stored as bcrypt hashes; the file is updated per
    user under a cross-process file lock and an atomic os.replace, so several
    processes registering at the same time cannot lose each other's updates.
  * The session cookie is an HMAC-signed token. Cookie name, signature key and
    expiry come exclusively from the [auth] table of .streamlit/config.toml,
    and keys.py generates / owns that key -- both sides share it, which is why
    a browser refresh keeps the user logged in.
  * Authentication runs before anything touches the xlsx file; the data is
    loaded and cached only after a successful login.

Trade-offs (deliberate, per task):
  1. Cookie lifetime is a FIXED 30-day absolute window from login (read from
     config, no sliding refresh). Rationale: predictable re-login frequency
     (roughly monthly) and a stable security boundary; sliding sessions would
     silently extend a stolen cookie forever.
  2. Registering an EXISTING username is REJECTED (old user/hash preserved);
     the page tells the user to pick another name or log in. Rationale:
     silently replacing credentials is an account-takeover vector, while a
     "first password wins" rule keeps the old account intact.
  3. A MISSING credentials file is auto-created empty on first start (so the
     login page works and offers registration), but a CORRUPT file is never
     silently overwritten: it is quarantined to credentials.corrupt-*.json and
     the app degrades to a login prompt. Rationale: no data loss on disk
     corruption / manual edits, and no crash on the request path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import tomllib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import bcrypt

BASE_DIR = Path(__file__).resolve().parent

# All on-disk paths are anchored at __file__; the env overrides exist only to
# let the test suite point the app at an isolated directory.
CONFIG_PATH = Path(os.environ.get("SALES_DASHBOARD_CONFIG", BASE_DIR / ".streamlit" / "config.toml"))
CREDENTIALS_PATH = Path(os.environ.get("SALES_DASHBOARD_CREDENTIALS", BASE_DIR / "credentials.json"))
DATA_PATH = Path(os.environ.get("SALES_DASHBOARD_DATA", BASE_DIR / "supermarkt_sales.xlsx"))


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def get_auth_settings(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Cookie name / signature key / expiry from config.toml only.

    If the [auth] table is missing or incomplete keys.py is used to repair it
    (that module owns key generation and never rotates an existing key), so a
    plain ``python app.py`` first run works out of the box.
    """
    settings: dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("rb") as fh:
            settings = tomllib.load(fh).get("auth", {}) or {}

    required = ("cookie_name", "cookie_key", "cookie_expiry_days")
    if not all(settings.get(key) for key in required):
        from keys import ensure_auth_config

        repaired = ensure_auth_config(config_path=config_path)
        settings.update({key: repaired[key] for key in required if not settings.get(key)})

    return {
        "cookie_name": str(settings["cookie_name"]),
        "cookie_key": str(settings["cookie_key"]),
        "cookie_expiry_days": int(settings["cookie_expiry_days"]),
    }


# --------------------------------------------------------------------------- #
# Credential store
# --------------------------------------------------------------------------- #
def _quarantine_path(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    candidate = path.with_name(f"{path.stem}.corrupt-{stamp}-{os.getpid()}{path.suffix}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(
            f"{path.stem}.corrupt-{stamp}-{os.getpid()}-{counter}{path.suffix}"
        )
        counter += 1
    return candidate


def load_credentials(
    path: Path | None = None,
) -> tuple[dict[str, dict[str, str]], str | None]:
    """Return (users, error).

    users maps username -> {"name": ..., "password": <bcrypt hash>}.
    error is None on success, "missing" when the file does not exist (caller
    may auto-create), or "corrupt" when it cannot be parsed/validated.
    """
    if path is None:
        path = CREDENTIALS_PATH
    if not path.exists():
        return {}, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        users = data["users"]
        if not isinstance(users, dict):
            raise ValueError("users must be an object")
        normalized: dict[str, dict[str, str]] = {}
        for username, record in users.items():
            if not isinstance(username, str) or not isinstance(record, dict):
                raise ValueError("bad record")
            name = record["name"]
            password_hash = record["password"]
            if not isinstance(name, str) or not isinstance(password_hash, str):
                raise ValueError("bad record")
            if not password_hash.startswith(("$2a$", "$2b$", "$2y$")):
                raise ValueError("non-bcrypt password on disk")
            normalized[username] = {"name": name, "password": password_hash}
        return normalized, None
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, OSError):
        return {}, "corrupt"


@contextmanager
def _file_lock(lock_path: Path):
    """Exclusive cross-process lock (busy-wait, works on all platforms)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import msvcrt

        fh = lock_path.open("a+b")
        try:
            while True:
                try:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.02)
            yield
        finally:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            fh.close()
    else:
        import fcntl

        fh = lock_path.open("a+b")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write JSON via a temp file + rename so readers never see a half file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.stem}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    os.replace(tmp_path, path)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

# --------------------------------------------------------------------------- #
# Registration (merge by username, never overwrite the whole file, no plaintext)
# --------------------------------------------------------------------------- #
REGISTER_OK = "ok"
REGISTER_EXISTS = "exists"
REGISTER_EMPTY = "empty"


def register_user(
    username: str,
    name: str,
    password: str,
    path: Path | None = None,
    overwrite: bool = False,
) -> bool:
    """Add one user. Returns True when newly created, False when rejected.

    Under the file lock we re-read the current file (merge by username instead
    of replacing it), then write through a temp file + os.replace. This is what
    makes concurrent registrations across processes lossless.
    """
    if path is None:
        path = CREDENTIALS_PATH
    username = (username or "").strip()
    name = (name or "").strip()
    if not username or not name or not password:
        return False

    lock_path = path.with_name(f"{path.name}.lock")
    with _file_lock(lock_path):
        users, error = load_credentials(path)
        if error == "corrupt":
            # Quarantine ONCE (rename, atomic) instead of clobbering, then
            # start from an empty store.
            quarantine = _quarantine_path(path)
            os.replace(path, quarantine)
            users = {}
        if username in users and not overwrite:
            return False

        users[username] = {"name": name, "password": hash_password(password)}
        _atomic_write_json(path, {"users": users})
        return True


def _concurrent_register_worker(args) -> str:
    """Top-level worker so multiprocessing (spawn on Windows) can pickle it."""
    path, username, name, password = args
    register_user(username, name, password, path=Path(path))
    return username


# --------------------------------------------------------------------------- #
# Signed session cookie
# --------------------------------------------------------------------------- #
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(token: str) -> bytes:
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


def create_auth_token(username: str, name: str, settings: dict) -> str:
    """HMAC-signed token: base64(payload).base64(hmac_sha256)."""
    expiry = int(time.time()) + int(settings["cookie_expiry_days"]) * 86400
    payload = json.dumps(
        {"u": username, "n": name, "exp": expiry}, separators=(",", ":"), sort_keys=True
    )
    payload_b64 = _b64encode(payload.encode("utf-8"))
    signature = hmac.new(
        settings["cookie_key"].encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{payload_b64}.{_b64encode(signature)}"


def parse_auth_token(token: str | None, settings: dict) -> dict | None:
    """Validate signature + expiry. Returns the payload dict or None."""
    if not token or not isinstance(token, str) or "." not in token:
        return None
    payload_b64, _, signature_b64 = token.rpartition(".")
    expected = hmac.new(
        settings["cookie_key"].encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).digest()
    try:
        provided = _b64decode(signature_b64)
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(expected, provided):
        return None
    try:
        payload = json.loads(_b64decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload


# --------------------------------------------------------------------------- #
# Authentication + ordering gate
# --------------------------------------------------------------------------- #
AUTH_OK = "ok"
AUTH_INVALID = "invalid"
AUTH_ANONYMOUS = "anonymous"


def authenticate(
    cookie_token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    settings: dict | None = None,
    credentials_path: Path | None = None,
) -> tuple[str, str | None, str | None]:
    """Authenticate a request. Returns (status, username, name).

    Credential paths are anchored at __file__ (see CREDENTIALS_PATH) and cookie
    settings come from config.toml via get_auth_settings, matching the key
    keys.py writes -- so a valid cookie survives refresh/restart.
    A corrupted credential store never raises: it simply behaves as
    "not logged in", letting the UI show the login prompt.
    """
    if settings is None:
        settings = get_auth_settings()
    if credentials_path is None:
        credentials_path = CREDENTIALS_PATH

    session = parse_auth_token(cookie_token, settings)
    if session is not None:
        return AUTH_OK, str(session.get("u", "")), str(session.get("n", ""))

    if username and password is not None:
        users, error = load_credentials(credentials_path)
        if error is None:
            record = users.get(username.strip())
            if record and verify_password(password, record["password"]):
                return AUTH_OK, username.strip(), record["name"]
        return AUTH_INVALID, None, None

    return AUTH_ANONYMOUS, None, None


def route_after_auth(
    cookie_token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    data_loader: Callable[[], Any] | None = None,
    settings: dict | None = None,
) -> tuple[str, str | None, str | None, Any]:
    """Gate keeping load_data(): it is invoked ONLY after auth succeeds.

    Returns (status, username, name, data) where data is None while the user
    is not authenticated -- load_data is never called in that case.
    """
    status, user, name = authenticate(cookie_token, username, password, settings)
    if status == AUTH_OK:
        data = data_loader() if data_loader is not None else load_data()
        return status, user, name, data
    return status, None, None, None

# --------------------------------------------------------------------------- #
# Data loading -- called only once authenticated (cached)
# --------------------------------------------------------------------------- #
def load_data() -> "pd.DataFrame":
    """Read the sales workbook. Path anchored at __file__, not the cwd."""
    import pandas as pd

    df = pd.read_excel(
        io=DATA_PATH,
        engine="openpyxl",
        sheet_name="Sales",
        skiprows=3,
        usecols="B:R",
        nrows=1000,
    )
    df["hour"] = pd.to_datetime(df["Time"], format="%H:%M:%S").dt.hour
    return df


# --------------------------------------------------------------------------- #
# Streamlit UI
# --------------------------------------------------------------------------- #
def _render_dashboard(df) -> None:
    import plotly.express as px
    import streamlit as st

    st.sidebar.title(f"Welcome {st.session_state.get('auth_name', '')}")
    st.sidebar.header("Please Filter Here:")
    city = st.sidebar.multiselect(
        "Select the City:", options=df["City"].unique(), default=df["City"].unique()
    )
    customer_type = st.sidebar.multiselect(
        "Select the Customer Type:",
        options=df["Customer_type"].unique(),
        default=df["Customer_type"].unique(),
    )
    gender = st.sidebar.multiselect(
        "Select the Gender:", options=df["Gender"].unique(), default=df["Gender"].unique()
    )

    df_selection = df.query(
        "City == @city & Customer_type == @customer_type & Gender == @gender"
    )

    st.title(":bar_chart: Sales Dashboard")
    st.success(f"You are logged in as **{st.session_state.get('auth_name', '')}**.")
    st.markdown("##")

    total_sales = int(df_selection["Total"].sum())
    average_rating = round(df_selection["Rating"].mean(), 1) if len(df_selection) else 0.0
    star_rating = ":star:" * int(round(average_rating, 0))
    average_sale_by_transaction = (
        round(df_selection["Total"].mean(), 2) if len(df_selection) else 0.0
    )
    left_column, middle_column, right_column = st.columns(3)
    with left_column:
        st.subheader("Total Sales:")
        st.subheader(f"US $ {total_sales:,}")
    with middle_column:
        st.subheader("Average Rating:")
        st.subheader(f"{average_rating} {star_rating}")
    with right_column:
        st.subheader("Average Sales Per Transaction:")
        st.subheader(f"US $ {average_sale_by_transaction}")

    st.markdown("""---""")

    # Select columns before summing: pandas 3 refuses to sum string columns.
    sales_by_product_line = (
        df_selection.groupby(by=["Product line"])[["Total"]]
        .sum()
        .sort_values(by="Total")
    )
    fig_product_sales = px.bar(
        sales_by_product_line,
        x="Total",
        y=sales_by_product_line.index,
        orientation="h",
        title="<b>Sales by Product Line</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_product_line),
        template="plotly_white",
    )
    fig_product_sales.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", xaxis=(dict(showgrid=False))
    )

    sales_by_hour = df_selection.groupby(by="hour")[["Total"]].sum()
    fig_hourly_sales = px.bar(
        sales_by_hour,
        x=sales_by_hour.index,
        y="Total",
        title="<b>Sales by hour</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_hour),
        template="plotly_white",
    )
    fig_hourly_sales.update_layout(
        xaxis=dict(tickmode="linear"),
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis=(dict(showgrid=False)),
    )

    left_column, right_column = st.columns(2)
    left_column.plotly_chart(fig_hourly_sales, width="stretch")
    right_column.plotly_chart(fig_product_sales, width="stretch")

    hide_st_style = """
                <style>
                #MainMenu {visibility: hidden;}
                footer {visibility: hidden;}
                header {visibility: hidden;}
                </style>
                """
    st.markdown(hide_st_style, unsafe_allow_html=True)


def main() -> None:
    import streamlit as st
    from extra_streamlit_components import CookieManager

    st.set_page_config(page_title="Sales Dashboard", page_icon=":bar_chart:", layout="wide")

    settings = get_auth_settings()
    cookie_name = settings["cookie_name"]

    # CookieManager uses a fixed internal component key ("init"), so it does
    # NOT remount between reruns even though we rebuild the Python wrapper:
    # Streamlit reconciles custom components by key, and the in-browser
    # component keeps serving its getAll() snapshot. Caching the wrapper in
    # session_state would instead hand us a stale component reference.
    cookies = CookieManager()
    stored_token = cookies.get(cookie_name)

    users, credentials_error = load_credentials()

    # --- Authenticate FIRST; load_data() is only reachable on AUTH_OK ---
    status, username, name = authenticate(cookie_token=stored_token, settings=settings)

    if status == AUTH_OK:
        st.session_state["auth_ok"] = True
        st.session_state["auth_user"] = username
        st.session_state["auth_name"] = name

        # Logout lives only inside the authenticated branch. Delete commits
        # during this run, so navigate with a meta refresh afterwards.
        if st.sidebar.button("Logout"):
            cookies.delete(cookie_name)
            st.session_state.clear()
            st.info("You have been logged out.")
            st.markdown(
                '<meta http-equiv="refresh" content="1;url=/">',
                unsafe_allow_html=True,
            )
            st.stop()

        @st.cache_data
        def get_cached_data():
            return load_data()

        df = get_cached_data()
        _render_dashboard(df)
        return

    # --- Not authenticated: login / registration only, xlsx never touched ---
    st.title(":bar_chart: Sales Dashboard")
    if credentials_error == "corrupt":
        st.warning(
            "The credentials file is corrupted, so login is temporarily "
            "unavailable. Please contact the administrator. (Your data was "
            "kept and quarantined; nothing crashed.)"
        )
    else:
        st.info("Please log in to view the dashboard, or register a new account.")

    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        if credentials_error == "corrupt":
            st.error("Login disabled until the credential store is repaired.")
        else:
            with st.form("login_form"):
                login_user = st.text_input("Username")
                login_password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Login")
            if submitted:
                login_status, login_username, login_name = authenticate(
                    username=login_user, password=login_password, settings=settings
                )
                if login_status == AUTH_OK:
                    token = create_auth_token(login_username, login_name, settings)
                    # Fixed absolute expiry (trade-off #1 in module docstring).
                    expires_at = datetime.now(timezone.utc) + timedelta(
                        days=settings["cookie_expiry_days"]
                    )
                    cookies.set(
                        cookie_name,
                        token,
                        key="set_login_cookie",
                        path="/",
                        expires_at=expires_at,
                        same_site="lax",
                    )
                    st.success(f"Welcome, {login_name}! Opening the dashboard...")
                    # The cookie component commits the cookie during THIS run
                    # and a plain st.rerun() would abort it before commit, so
                    # trigger a full-page navigation instead (meta refresh is
                    # not sanitized like <script>); the next load reads the
                    # cookie via authenticate() and stays logged in on refresh.
                    st.markdown(
                        '<meta http-equiv="refresh" content="1;url=/">',
                        unsafe_allow_html=True,
                    )
                else:
                    st.error("Username/password is incorrect")

    with tab_register:
        if credentials_error == "corrupt":
            st.error("Registration is disabled until the credential store is repaired.")
        else:
            with st.form("register_form", clear_on_submit=True):
                reg_name = st.text_input("Your name")
                reg_user = st.text_input("Choose a username")
                reg_password = st.text_input("Choose a password", type="password")
                register_submitted = st.form_submit_button("Create account")
            if register_submitted:
                # Existing username is rejected, never overwritten (trade-off
                # #2 in the module docstring). clear_on_submit keeps the same
                # name from being re-submitted with an appended/edited value.
                created = register_user(reg_user, reg_name, reg_password)
                if created:
                    st.success("Account created. You can log in on the Login tab.")
                else:
                    st.warning(
                        "That username is already taken (or a field was empty). "
                        "Please choose another username or log in instead."
                    )


def _launch_streamlit() -> None:
    """`python app.py` -> streamlit on port 8000 (see config.toml [server]).

    We are already running inside streamlit when our marker env var is set
    (streamlit re-executes this same file as a child process), so just render.
    Otherwise spawn streamlit ourselves and wait for it so Ctrl-C propagates.
    """
    import subprocess

    # Detect the streamlit runtime itself (streamlit run AND AppTest both set
    # up a ScriptRunContext); only a bare `python app.py` should spawn the
    # server subprocess.
    if os.environ.get("SALES_DASHBOARD_UNDER_STREAMLIT") == "1":
        main()
        return
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        if get_script_run_ctx() is not None:
            main()
            return
    except Exception:
        pass

    env = os.environ.copy()
    env["SALES_DASHBOARD_UNDER_STREAMLIT"] = "1"
    script = str(Path(__file__).resolve())
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            script,
            "--server.port=8000",
            "--server.headless=true",
        ],
        env=env,
    )
    sys.exit(proc.returncode)


if __name__ == "__main__":
    _launch_streamlit()

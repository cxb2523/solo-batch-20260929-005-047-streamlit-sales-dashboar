"""Login gate and credential persistence for the sales dashboard.

Design decisions (the three trade-offs called out in the task):

1. Cookie lifetime vs. how often users must log in:
   Fixed 7-day expiry ("cookie_expiry_days" in config.toml), no sliding
   renewal. A fixed window bounds how long a stolen cookie remains valid
   while keeping re-login rare enough for an internal dashboard. Renewal
   happens only through a successful password check, so merely browsing
   can never extend a session.

2. Duplicate username on registration -> reject, never overwrite:
   register_user raises UserExistsError and keeps the stored bcrypt hash.
   Silently replacing an account would let anyone who guesses a username
   hijack it; the UI turns this into a visible "choose another username"
   message.

3. Missing credentials file on first start -> auto-provision, do not error:
   ensure_credentials() creates an empty store ({} users) so the very
   first launch works and users can self-register; an empty store grants
   nobody access. A *corrupt* file is different: load_credentials raises
   CredentialsError and the UI degrades to a login warning instead of
   crashing, so possible data loss is never masked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import msvcrt
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import bcrypt
import toml

try:
    import pandas as pd
except Exception:  # pragma: no cover - pandas is a runtime requirement
    pd = None


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / ".streamlit" / "config.toml"
DATA_PATH = BASE_DIR / "supermarkt_sales.xlsx"

DEFAULT_COOKIE_NAME = "sales_dashboard_auth"
DEFAULT_COOKIE_EXPIRY_DAYS = 7
LOCK_TIMEOUT_SECONDS = 10.0


class AuthError(Exception):
    """Base class for authentication/persistence errors."""


class UserExistsError(AuthError):
    """Raised when registration targets an existing username."""


class CredentialsError(AuthError):
    """Raised when the credentials file cannot be parsed."""


# --------------------------------------------------------------------------- #
# config.toml
# --------------------------------------------------------------------------- #
def load_config(config_path: str | Path = CONFIG_PATH) -> dict[str, Any]:
    """Load .streamlit/config.toml (cookie name / key / expiry live there)."""
    path = Path(config_path)
    if not path.is_file():
        raise AuthError(f"config.toml not found: {path}")
    return toml.loads(path.read_text(encoding="utf-8"))


def get_auth_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return cookie/credential settings from the [auth] section.

    cookie_name / cookie_key / cookie_expiry_days MUST be read from one
    place (config.toml) and keys.py writes the same cookie_key, otherwise
    cookies signed here do not validate after a refresh.
    """
    config = config if config is not None else load_config()
    section = config.get("auth", {})
    cookie_key = section.get("cookie_key")
    if not cookie_key:
        raise AuthError("config.toml [auth] cookie_key is missing; run: python keys.py")
    settings = {
        "cookie_name": str(section.get("cookie_name", DEFAULT_COOKIE_NAME)),
        "cookie_key": str(cookie_key),
        "cookie_expiry_days": float(
            section.get("cookie_expiry_days", DEFAULT_COOKIE_EXPIRY_DAYS)
        ),
        "credentials_file": str(
            section.get("credentials_file", "credentials.json")
        ),
    }
    cred_path = Path(settings["credentials_file"])
    if not cred_path.is_absolute():
        # Always anchored at this file's directory, independent of CWD.
        cred_path = BASE_DIR / cred_path
    settings["credentials_path"] = cred_path
    return settings


# --------------------------------------------------------------------------- #
# credentials file (bcrypt hashes only, JSON, merge by username)
# --------------------------------------------------------------------------- #
def _empty_store() -> dict[str, Any]:
    return {"users": {}}


def load_credentials(path: str | Path | None = None) -> dict[str, Any]:
    """Load the credential store. Missing -> empty store; corrupt -> error."""
    path = Path(path) if path is not None else get_auth_settings()["credentials_path"]
    if not path.exists():
        return _empty_store()
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CredentialsError(f"credentials file is corrupt: {path}") from exc
    if not isinstance(store, dict) or not isinstance(store.get("users"), dict):
        raise CredentialsError(f"credentials file has an invalid structure: {path}")
    return store


def ensure_credentials(path: str | Path | None = None) -> Path:
    """First-run provisioning: create an empty store if it does not exist."""
    path = Path(path) if path is not None else get_auth_settings()["credentials_path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _atomic_write_json(path, _empty_store())
    return path


class _FileLock:
    """Cross-process lock for the credentials file (Windows msvcrt / POSIX flock)."""

    def __init__(self, target: Path, timeout: float = LOCK_TIMEOUT_SECONDS):
        self._target = target
        self._lock_path = target.with_suffix(target.suffix + ".lock")
        self._timeout = timeout
        self._fh = None

    def __enter__(self) -> "_FileLock":
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._lock_path, "a+b")
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                if os.name == "nt":
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    self._fh = None
                    raise AuthError(
                        f"timed out waiting for credentials lock: {self._lock_path}"
                    )
                time.sleep(0.02)

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            try:
                if os.name == "nt":
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write to a temp file in the same directory then os.replace (atomic rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def register_user(
    username: str,
    password: str,
    name: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Register one user under a file lock.

    Re-reads the store while holding the lock so concurrent registrations in
    different processes merge by username instead of overwriting each other.
    Raises UserExistsError on duplicate usernames (case-insensitive).
    """
    username = (username or "").strip()
    if not username:
        raise AuthError("username must not be empty")
    if not password:
        raise AuthError("password must not be empty")

    cred_path = Path(path) if path is not None else get_auth_settings()["credentials_path"]
    ensure_credentials(cred_path)
    with _FileLock(cred_path):
        store = load_credentials(cred_path)
        users = store["users"]
        if username.lower() in {existing.lower() for existing in users}:
            # Reject: keep the old account/hash untouched (no overwrite).
            raise UserExistsError(f"username already exists: {username}")
        users[username] = {
            "name": (name or username).strip() or username,
            "password_hash": hash_password(password),
            "created_at": int(time.time()),
        }
        _atomic_write_json(cred_path, store)
    return users[username]


# --------------------------------------------------------------------------- #
# signed cookie token (HMAC, aligned with keys.py's cookie_key in config.toml)
# --------------------------------------------------------------------------- #
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def create_cookie_token(
    username: str,
    cookie_key: str,
    cookie_expiry_days: float,
    now: float | None = None,
) -> str:
    issued = int(now if now is not None else time.time())
    expires = issued + int(cookie_expiry_days * 24 * 60 * 60)
    payload = _b64encode(
        json.dumps({"u": username, "iat": issued, "exp": expires}, separators=(",", ":")).encode()
    )
    signature = _b64encode(
        hmac.new(cookie_key.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def parse_cookie_token(token: str, cookie_key: str, now: float | None = None) -> str | None:
    """Return the username if the token is correctly signed and unexpired."""
    if not token or not isinstance(token, str) or token.count(".") != 1:
        return None
    payload_b64, signature_b64 = token.split(".", 1)
    expected = _b64encode(
        hmac.new(cookie_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected, signature_b64):
        return None
    try:
        payload = json.loads(_b64decode(payload_b64))
        expires = float(payload["exp"])
        username = str(payload["u"])
    except (ValueError, KeyError, TypeError):
        return None
    if expires < (now if now is not None else time.time()):
        return None
    return username


@dataclass
class AuthResult:
    status: bool | None  # True=logged in, False=bad credentials, None=anonymous
    username: str | None = None
    name: str | None = None
    token: str | None = None
    message: str = ""


def authenticate(
    credentials: dict[str, Any],
    submitted_username: str | None = None,
    submitted_password: str | None = None,
    cookie_token: str | None = None,
    settings: dict[str, Any] | None = None,
) -> AuthResult:
    """Pure gate: validate form login first, then the signed cookie.

    ``credentials`` is the already-loaded store. The caller decides what to do
    when the file is corrupt (degrade to the login prompt), and load_data()
    must not run before this returns status True.
    """
    settings = settings if settings is not None else get_auth_settings()
    users = credentials.get("users", {})

    # 1) Explicit form submission takes priority.
    if submitted_username is not None or submitted_password is not None:
        submitted_username = (submitted_username or "").strip()
        record = _find_user(users, submitted_username)
        if record and verify_password(submitted_password or "", record["password_hash"]):
            token = create_cookie_token(
                submitted_username,
                settings["cookie_key"],
                settings["cookie_expiry_days"],
            )
            return AuthResult(True, submitted_username, record.get("name"), token, "login ok")
        return AuthResult(False, message="Username/password is incorrect")

    # 2) No form submission: honour a valid cookie -> stays logged in on refresh.
    if cookie_token:
        cookie_username = parse_cookie_token(cookie_token, settings["cookie_key"])
        if cookie_username is not None:
            record = _find_user(users, cookie_username)
            if record is not None:
                return AuthResult(True, cookie_username, record.get("name"), None, "cookie ok")

    return AuthResult(None, message="Please enter your username and password")


def _find_user(users: dict[str, dict], username: str) -> dict[str, Any] | None:
    for existing, record in users.items():
        if existing.lower() == username.lower():
            return record
    return None


def load_data() -> "pd.DataFrame":
    """Read the xlsx once (cached by Streamlit); only call after login."""
    return _load_data_cached(str(DATA_PATH))


def _do_load(path: str):  # pragma: no cover - thin pandas wrapper
    df = pd.read_excel(
        io=path,
        engine="openpyxl",
        sheet_name="Sales",
        skiprows=3,
        usecols="B:R",
        nrows=1000,
    )
    df["hour"] = pd.to_datetime(df["Time"], format="%H:%M:%S").dt.hour
    return df


try:
    import streamlit as st

    _load_data_cached = st.cache_data(_do_load)
except Exception:  # pragma: no cover - allows importing without streamlit
    _load_data_cached = _do_load


def new_secret_key(length: int = 32) -> str:
    """Cookie signing key written by keys.py (kept here for reuse)."""
    return secrets.token_urlsafe(length)

"""Sales Dashboard with a login gate.

Startup order is strict:

  config.toml [auth] -> credentials file -> authenticate() -> (only after a
  successful login) load_data() reads supermarkt_sales.xlsx (cached)

No xlsx data is ever loaded for anonymous or failed logins. A corrupt
credentials file degrades to the login prompt instead of crashing.

Trade-offs (called out explicitly, see also auth.py / keys.py):
  * cookie lifetime is a fixed 7 days from config.toml, no sliding renewal;
  * duplicate usernames are rejected on registration (old hash preserved);
  * a missing credentials file is auto-provisioned empty on first start.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

import auth

st.set_page_config(page_title="Sales Dashboard", page_icon=":bar_chart:", layout="wide")


# --------------------------------------------------------------------------- #
# Browser cookie bridge
# --------------------------------------------------------------------------- #
# One CookieManager per Streamlit process, reused across reruns. Creating a new
# one per rerun remounts the frontend iframe and loses pending cookie writes
# (the "refresh drops the login" bug); storing one in session_state is worse -
# it serialises into a plain dict and get() returns None forever.
_COOKIE_MANAGER = None


def _cookie_manager():
    global _COOKIE_MANAGER
    if _COOKIE_MANAGER is None:
        from extra_streamlit_components.CookieManager import CookieManager

        _COOKIE_MANAGER = CookieManager(key="sales_cookies")
    return _COOKIE_MANAGER


def _set_auth_cookie(token: str, settings: dict) -> None:
    import datetime

    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=settings["cookie_expiry_days"]
    )
    _cookie_manager().set(
        settings["cookie_name"],
        token,
        key="set_auth_cookie",
        path="/",
        expires_at=expires,
        same_site="lax",
    )


def _logout_reload_js(cookie_name: str) -> None:
    """Expire the auth cookie in the TOP document, then hard-reload.

    The cookie component's delete()/expiry calls are unreliable across the
    reruns a logout triggers, and its iframe is sandboxed so it cannot touch
    the top document at all. st.html(unsafe_allow_javascript=True) runs in the
    main frame, where document.cookie + location.reload() work directly. The
    fresh document load has no cookie, so it lands on the login page with no
    stale dashboard delta left behind.
    """
    st.html(
        f"""
        <script>
          document.cookie = {cookie_name!r} + "=; path=/; max-age=0; SameSite=Lax";
          document.cookie = {cookie_name!r} + "=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax";
          window.location.reload();
        </script>
        """,
        unsafe_allow_javascript=True,
    )


# --------------------------------------------------------------------------- #
# Gate UI
# --------------------------------------------------------------------------- #
def _on_logout_click() -> None:
    # The callback runs before the script body, so the follow-up rerun enters
    # main() with pending_logout set before any widget is touched.
    st.session_state["pending_logout"] = True


def _show_login_or_register(settings: dict, credentials: dict):
    """Return (username, name) when authenticated, otherwise (None, None)."""
    ss = st.session_state
    pending_login = ss.get("pending_login")
    cookie_warning = None

    if not pending_login:
        # The component answers get() one run behind on a fresh page load and
        # triggers its own rerun when cookies arrive, so no manual st.rerun()
        # is needed (forced reruns were observed to swallow sidebar clicks).
        cookie_token = _cookie_manager().get(settings["cookie_name"])
        if cookie_token:
            result = auth.authenticate(
                credentials, cookie_token=cookie_token, settings=settings
            )
            if result.status is True:
                # The browser cookie now owns the session; drop the one-shot
                # post-login override so logout cannot be bypassed.
                ss.pop("pending_login", None)
                return result.username, result.name
            cookie_warning = "Your session has expired, please log in again."
        else:
            cookie_warning = "Please enter your username and password"

    st.title(":bar_chart: Sales Dashboard")
    tab_login, tab_register = st.tabs(["Login", "Register"])

    if cookie_warning:
        st.warning(cookie_warning)

    with tab_login:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")

        if submitted:
            result = auth.authenticate(
                credentials,
                submitted_username=username,
                submitted_password=password,
                settings=settings,
            )
            if result.status is True:
                # Queue the cookie write AND render the dashboard this run;
                # pending_login covers the next run in case the component's
                # own post-set rerun happens before paint.
                _set_auth_cookie(result.token, settings)
                ss["pending_login"] = (result.username, result.name)
                return result.username, result.name
            st.error(result.message)
            return None, None
        elif pending_login:
            username, name = ss.pop("pending_login")
            return username, name

    with tab_register:
        with st.form("register_form"):
            new_name = st.text_input("Your name")
            new_username = st.text_input("Choose a username")
            new_password = st.text_input("Choose a password", type="password")
            register_clicked = st.form_submit_button("Create account")

        if register_clicked:
            try:
                auth.register_user(
                    new_username,
                    new_password,
                    name=new_name,
                    path=settings["credentials_path"],
                )
            except auth.UserExistsError:
                st.error("That username is already taken — please choose another.")
            except auth.AuthError as exc:
                st.error(str(exc))
            else:
                st.success("Account created. You can now log in from the Login tab.")

    return None, None


# --------------------------------------------------------------------------- #
# Dashboard (only reached after authentication)
# --------------------------------------------------------------------------- #
def _show_dashboard(name: str) -> None:
    df = auth.load_data()  # cached via st.cache_data; never runs pre-login

    with st.sidebar:
        st.button("Logout", key="logout_btn", on_click=_on_logout_click)
        st.title(f"Welcome {name}")
        st.header("Please Filter Here:")
        city = st.multiselect(
            "Select the City:", options=df["City"].unique(), default=df["City"].unique()
        )
        customer_type = st.multiselect(
            "Select the Customer Type:",
            options=df["Customer_type"].unique(),
            default=df["Customer_type"].unique(),
        )
        gender = st.multiselect(
            "Select the Gender:", options=df["Gender"].unique(),
            default=df["Gender"].unique(),
        )

    df_selection = df.query(
        "City == @city & Customer_type == @customer_type & Gender == @gender"
    )

    import plotly.express as px

    st.title(":bar_chart: Sales Dashboard")
    st.markdown("##")

    total_sales = int(df_selection["Total"].sum())
    average_rating = round(df_selection["Rating"].mean(), 1)
    star_rating = ":star:" * int(round(average_rating, 0))
    average_sale_by_transaction = round(df_selection["Total"].mean(), 2)

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

    sales_by_product_line = (
        df_selection.groupby(by=["Product line"])[["Total"]].sum().sort_values(by="Total")
    )
    fig_product_sales = px.bar(
        sales_by_product_line, x="Total", y=sales_by_product_line.index,
        orientation="h", title="<b>Sales by Product Line</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_product_line),
        template="plotly_white",
    )
    fig_product_sales.update_layout(plot_bgcolor="rgba(0,0,0,0)",
                                    xaxis=dict(showgrid=False))

    sales_by_hour = df_selection.groupby(by=["hour"])[["Total"]].sum()
    fig_hourly_sales = px.bar(
        sales_by_hour, x=sales_by_hour.index, y="Total",
        title="<b>Sales by hour</b>",
        color_discrete_sequence=["#0083B8"] * len(sales_by_hour),
        template="plotly_white",
    )
    fig_hourly_sales.update_layout(xaxis=dict(tickmode="linear"),
                                   plot_bgcolor="rgba(0,0,0,0)",
                                   yaxis=dict(showgrid=False))

    left_column, right_column = st.columns(2)
    left_column.plotly_chart(fig_hourly_sales, use_container_width=True)
    right_column.plotly_chart(fig_product_sales, use_container_width=True)

    st.markdown(
        """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        </style>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def main() -> None:
    # Logout rerun: clear server-side state first, then let top-frame JS remove
    # the cookie and hard-reload. No dashboard element is created on this run.
    if st.session_state.get("pending_logout"):
        st.session_state.pop("pending_logout", None)
        st.session_state.pop("pending_login", None)
        try:
            logout_settings = auth.get_auth_settings()
        except auth.AuthError:
            st.warning("Please contact the administrator or run: python keys.py")
            return
        _logout_reload_js(logout_settings["cookie_name"])
        st.info("Logging you out…")
        return

    try:
        settings = auth.get_auth_settings()
        # First launch: provision an empty store automatically (grants nobody
        # access; users self-register). A CORRUPT file is different and raises.
        auth.ensure_credentials(settings["credentials_path"])
        credentials = auth.load_credentials(settings["credentials_path"])
    except auth.CredentialsError as exc:
        # Corrupt credentials file: degrade to the login prompt, never crash,
        # and never touch load_data(). The file is deliberately NOT
        # auto-overwritten (that would silently destroy credential data);
        # show the neutral prompt so the page still looks like a login page.
        st.error(str(exc))
        st.title(":bar_chart: Sales Dashboard")
        st.warning(
            "Login is temporarily unavailable because the credentials file is "
            "corrupt. Please contact the administrator."
        )
        return
    except auth.AuthError as exc:
        # Missing signing key etc.: actionable message, never a crash.
        st.error(str(exc))
        st.warning("Please contact the administrator or run: python keys.py")
        return

    username, name = _show_login_or_register(settings, credentials)
    if username is None:
        return  # Gate closed: load_data() is never reached.

    _show_dashboard(name or username)


def _run_streamlit() -> None:
    if os.environ.get("SALES_DASHBOARD_STREAMLIT") == "1":
        return  # already inside `streamlit run`
    os.environ["SALES_DASHBOARD_STREAMLIT"] = "1"
    import subprocess

    script = str(Path(__file__).resolve())
    sys.exit(
        subprocess.call(
            [
                sys.executable, "-m", "streamlit", "run", script,
                "--server.port=8000",
                "--server.address=127.0.0.1",
                "--global.developmentMode=false",
            ]
        )
    )


if __name__ == "__main__":
    # Outside streamlit this relaunches through `streamlit run` on port 8000;
    # inside streamlit the env guard makes it a no-op and main() runs.
    _run_streamlit()
    main()

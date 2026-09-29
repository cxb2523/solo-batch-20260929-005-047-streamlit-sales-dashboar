"""Provision secrets used by app.py.

Run:  python keys.py

It writes the cookie signing key ("cookie_key"), cookie name and expiry
into the [auth] section of .streamlit/config.toml. app.py reads those exact
values, so the signer and the verifier always agree and a refresh keeps the
login session. tomlkit preserves the existing [theme] settings and keeps
comments readable.

Decision: keys.py never rotates an existing cookie_key. Rotating would
silently invalidate every logged-in user's cookie on each deploy/run. Delete
the key (or the [auth] section) deliberately if rotation is wanted.
"""

from __future__ import annotations

from pathlib import Path

import tomlkit

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / ".streamlit" / "config.toml"

DEFAULT_COOKIE_NAME = "sales_dashboard_auth"
DEFAULT_COOKIE_EXPIRY_DAYS = 7


def _new_cookie_key() -> str:
    import secrets

    return secrets.token_urlsafe(32)


def write_cookie_key(config_path: Path = CONFIG_PATH) -> str:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    else:
        document = tomlkit.document()

    auth = document.get("auth")
    if auth is None:
        auth = tomlkit.table()
        document["auth"] = auth

    auth.setdefault("cookie_name", DEFAULT_COOKIE_NAME)
    auth.setdefault("cookie_expiry_days", DEFAULT_COOKIE_EXPIRY_DAYS)
    auth.setdefault("credentials_file", "credentials.json")

    existing = auth.get("cookie_key")
    if existing:
        print(f"cookie_key already present in {config_path}; keeping it (no rotation).")
        return str(existing)

    key = _new_cookie_key()
    auth["cookie_key"] = key
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")
    print(f"Wrote new cookie_key to {config_path}.")
    return key


def generate_password_hashes(passwords: list[str]) -> list[str]:
    """Kept for parity with the original generate_keys.py workflow."""
    import bcrypt

    return [
        bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        for p in passwords
    ]


if __name__ == "__main__":
    write_cookie_key()

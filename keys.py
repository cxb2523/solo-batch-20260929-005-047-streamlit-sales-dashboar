"""Credential / cookie-key bootstrap for the sales dashboard.

Responsibilities:
  * keep the [auth] section of .streamlit/config.toml in sync: generate a
    random cookie signature key on first run (never overwrite an existing
    one) and make sure the cookie name / expiry are present;
  * create an empty credentials store on first start so the login page can
    offer self-service registration;
  * optionally seed users (used by the legacy generate_keys.py shim and by
    ``python keys.py <user> <name> <password>``).

The values written here are the single source of truth read by app.py, which
is why a refresh does not drop the login session: the cookie is signed with
exactly this key and checked under exactly this cookie name.
"""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

import bcrypt
import tomlkit

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / ".streamlit" / "config.toml"
CREDENTIALS_PATH = BASE_DIR / "credentials.json"

DEFAULT_COOKIE_NAME = "sales_dashboard_auth"
DEFAULT_COOKIE_EXPIRY_DAYS = 30

# The legacy video tutorial seeded hashed_pw.pkl with two demo accounts whose
# real passwords are unknown ("XXX"). We deliberately do not migrate that file
# into credentials.json: importing unknown/empty demo credentials would just
# create accounts nobody can actually log in with.


def load_config() -> tomlkit.TOMLDocument:
    if CONFIG_PATH.exists():
        return tomlkit.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    return tomlkit.document()


def ensure_auth_config(
    config_path: Path = CONFIG_PATH,
    cookie_name: str = DEFAULT_COOKIE_NAME,
    cookie_expiry_days: int = DEFAULT_COOKIE_EXPIRY_DAYS,
) -> dict:
    """Ensure the [auth] section exists and return its values.

    The signature key is generated once and kept stable: rotating it on every
    start would invalidate every issued cookie and users would be logged out
    on each refresh/restart.
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    doc = load_config() if config_path.exists() else tomlkit.document()

    auth = doc.get("auth")
    if auth is None:
        auth = tomlkit.table()
        doc["auth"] = auth
        auth["cookie_name"] = cookie_name
        auth["cookie_key"] = secrets.token_hex(32)
        auth["cookie_expiry_days"] = cookie_expiry_days

    changed = False
    if "cookie_name" not in auth:
        auth["cookie_name"] = cookie_name
        changed = True
    # "PLACEHOLDER" is the value shipped in the repo template; treat it
    # as missing so the first run replaces it with a real random key.
    if str(auth.get("cookie_key", "")).strip() in ("", "PLACEHOLDER"):
        auth["cookie_key"] = secrets.token_hex(32)
        changed = True
    if "cookie_expiry_days" not in auth:
        auth["cookie_expiry_days"] = cookie_expiry_days
        changed = True

    if changed or not config_path.exists():
        config_path.write_text(tomlkit.dumps(doc), encoding="utf-8")

    return {
        "cookie_name": str(auth["cookie_name"]),
        "cookie_key": str(auth["cookie_key"]),
        "cookie_expiry_days": int(auth["cookie_expiry_days"]),
    }


def seed_user(username: str, name: str, password: str) -> bool:
    """Create or reset one user. Returns True if a new account was created."""
    # Imported lazily so this module stays importable without touching the
    # locking primitives when callers only need ensure_auth_config.
    from app import register_user

    return register_user(
        username=username,
        name=name,
        password=password,
        overwrite=True,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bootstrap auth config/users.")
    parser.add_argument("username", nargs="?", help="username to seed")
    parser.add_argument("name", nargs="?", help="display name")
    parser.add_argument("password", nargs="?", help="plaintext password")
    args = parser.parse_args(argv)

    auth = ensure_auth_config()
    print(
        "auth config ready: "
        f"cookie_name={auth['cookie_name']} "
        f"cookie_expiry_days={auth['cookie_expiry_days']} "
        f"key=<{len(auth['cookie_key'])} hex chars>"
    )

    if args.username:
        if not args.name or not args.password:
            parser.error("seeding a user requires username, name and password")
        created = seed_user(args.username, args.name, args.password)
        action = "seeded" if created else "updated"
        print(f"user '{args.username}' {action} in {CREDENTIALS_PATH}")
    else:
        print(
            "tip: self-service registration is available on the login page, "
            "or seed a user with: python keys.py <username> <name> <password>"
        )


if __name__ == "__main__":
    main()

"""Auth flow tests for the Streamlit sales dashboard.

Covers the four acceptance scenarios:
  1. refresh keeps the login (signed cookie validated with the config key);
  2. registering an existing user keeps the old account/hash;
  3. a corrupted credentials file degrades to a login prompt, no crash;
  4. concurrent registrations across processes lose no updates.

Also asserts the ordering gate: load_data() must never run before auth.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import sys
import time
from pathlib import Path

import pytest

import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def isolated_store(tmp_path, monkeypatch):
    config_path = tmp_path / ".streamlit" / "config.toml"
    creds_path = tmp_path / "credentials.json"

    from keys import ensure_auth_config

    settings = ensure_auth_config(config_path=config_path)

    monkeypatch.setattr(app, "CONFIG_PATH", config_path)
    monkeypatch.setattr(app, "CREDENTIALS_PATH", creds_path)
    monkeypatch.setattr(app, "DATA_PATH", tmp_path / "does-not-exist.xlsx")

    return {"tmp": tmp_path, "config": config_path, "creds": creds_path, "settings": settings}


# --------------------------------------------------------------------------- #
# 1. Refresh keeps the user logged in + no data loading before auth
# --------------------------------------------------------------------------- #
def test_login_then_refresh_still_logged_in(isolated_store):
    settings = isolated_store["settings"]
    creds = isolated_store["creds"]

    assert app.register_user("alice", "Alice Wang", "s3cret!", path=creds) is True

    # First request: username/password form login.
    status, user, name = app.authenticate(username="alice", password="s3cret!", settings=settings)
    assert status == app.AUTH_OK
    assert user == "alice"
    assert name == "Alice Wang"

    # Server issues a signed cookie after login.
    token = app.create_auth_token(user, name, settings)

    # "Refresh" = new request carrying only the cookie, no form fields.
    status2, user2, name2 = app.authenticate(cookie_token=token, settings=settings)
    assert status2 == app.AUTH_OK
    assert (user2, name2) == ("alice", "Alice Wang")

    # Cookies are bound to the config key: a different key rejects them,
    # which is why keys.py must never rotate the key silently.
    forged_settings = dict(settings, cookie_key="0" * 64)
    assert app.parse_auth_token(token, forged_settings) is None

    # Tampered payload is rejected too.
    payload, _, sig = token.partition(".")
    assert app.parse_auth_token(payload + "." + sig[:-2] + "aa", settings) is None


def test_expired_or_garbage_cookie_is_anonymous(isolated_store):
    settings = isolated_store["settings"]
    assert app.authenticate(cookie_token=None, settings=settings)[0] == app.AUTH_ANONYMOUS
    assert app.authenticate(cookie_token="not-a-token", settings=settings)[0] == app.AUTH_ANONYMOUS

    expired = dict(settings, cookie_expiry_days=-1)
    stale_token = app.create_auth_token("alice", "Alice", expired)
    assert app.parse_auth_token(stale_token, settings) is None


def test_data_loader_never_runs_before_auth(isolated_store):
    """load_data() is unreachable until authentication passes."""
    settings = isolated_store["settings"]

    def boom():
        raise AssertionError("load_data must not run before authentication")

    status, _, _, data = app.route_after_auth(data_loader=boom)
    assert status == app.AUTH_ANONYMOUS
    assert data is None

    status, _, _, data = app.route_after_auth(
        username="ghost", password="nope", data_loader=boom, settings=settings
    )
    assert status == app.AUTH_INVALID
    assert data is None

    # After a successful login the (cached) loader is the thing that runs.
    app.register_user("bob", "Bob Li", "pw-12345", path=isolated_store["creds"])
    sentinel = object()
    status, user, name, data = app.route_after_auth(
        username="bob", password="pw-12345", data_loader=lambda: sentinel, settings=settings
    )
    assert status == app.AUTH_OK
    assert user == "bob"
    assert data is sentinel


# --------------------------------------------------------------------------- #
# 2. Duplicate registration preserves the old user
# --------------------------------------------------------------------------- #
def test_duplicate_registration_keeps_old_user(isolated_store):
    creds = isolated_store["creds"]

    assert app.register_user("carol", "Carol One", "first-password", path=creds) is True
    users, error = app.load_credentials(creds)
    assert error is None
    first_hash = users["carol"]["password"]
    assert first_hash != "first-password"  # never plaintext
    assert first_hash.startswith(("$2a$", "$2b$", "$2y$"))

    # Second attempt with the same username must be rejected...
    assert app.register_user("carol", "Carol Two", "second-password", path=creds) is False

    # ...the old hash/name survive, and only one user exists.
    users, error = app.load_credentials(creds)
    assert error is None
    assert set(users) == {"carol"}
    assert users["carol"]["name"] == "Carol One"
    assert users["carol"]["password"] == first_hash
    assert app.verify_password("first-password", users["carol"]["password"])
    assert not app.verify_password("second-password", users["carol"]["password"])

    # Other users are still registrable (merge, not overwrite).
    assert app.register_user("dave", "Dave K", "abc-123", path=creds) is True
    users, _ = app.load_credentials(creds)
    assert set(users) == {"carol", "dave"}


def test_store_file_is_json_with_bcrypt_only(isolated_store):
    creds = isolated_store["creds"]
    app.register_user("erin", "Erin", "plaintext-on-wire", path=creds)
    raw = json.loads(creds.read_text(encoding="utf-8"))
    assert set(raw) == {"users"}
    record = raw["users"]["erin"]
    assert record["name"] == "Erin"
    assert "plaintext-on-wire" not in creds.read_text(encoding="utf-8")
    assert record["password"].startswith(("$2a$", "$2b$", "$2y$"))


# --------------------------------------------------------------------------- #
# 3. Corrupted credential file -> login prompt, never a crash
# --------------------------------------------------------------------------- #
def test_corrupt_credentials_degrade_to_login_prompt(isolated_store):
    creds = isolated_store["creds"]
    settings = isolated_store["settings"]
    app.register_user("frank", "Frank", "good-pw", path=creds)

    creds.write_text("{ this is : not valid json,,,", encoding="utf-8")

    # Loading reports "corrupt" instead of raising.
    users, error = app.load_credentials(creds)
    assert error == "corrupt"
    assert users == {}

    # authenticate() still returns a normal status (invalid/anonymous),
    # i.e. the UI can degrade to its login prompt.
    status, _, _ = app.authenticate(
        username="frank", password="good-pw", settings=settings
    )
    assert status == app.AUTH_INVALID
    status, _, _ = app.authenticate(cookie_token=None, settings=settings)
    assert status == app.AUTH_ANONYMOUS

    # Valid-but-wrong-shaped content and plaintext are also "corrupt".
    creds.write_text(json.dumps({"users": {"x": {"name": "X", "password": "plain"}}}),
                     encoding="utf-8")
    _, error = app.load_credentials(creds)
    assert error == "corrupt"
    creds.write_text(json.dumps({"nope": {}}), encoding="utf-8")
    _, error = app.load_credentials(creds)
    assert error == "corrupt"


def test_corrupt_file_quarantined_not_destroyed_on_register(isolated_store):
    creds = isolated_store["creds"]
    creds.write_text("garbage", encoding="utf-8")

    assert app.register_user("grace", "Grace", "pw!", path=creds) is True

    quarantined = sorted(creds.parent.glob("credentials.corrupt-*.json"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == "garbage"

    users, error = app.load_credentials(creds)
    assert error is None
    assert set(users) == {"grace"}


# --------------------------------------------------------------------------- #
# 4. Concurrent registrations across processes lose no updates
# --------------------------------------------------------------------------- #
def _register_args(creds_path, userspecs):
    return [(str(creds_path), u, n, pw) for u, n, pw in userspecs]


def test_concurrent_registrations_no_lost_updates(isolated_store):
    creds = isolated_store["creds"]
    app.register_user("seed", "Seed User", "seed-pw", path=creds)

    distinct = [(f"user{i}", f"User {i}", f"password-{i}") for i in range(6)]
    # Four processes racing to create the SAME username: exactly one must win,
    # the others must be rejected, and the file must stay valid JSON.
    same_name = [("raceuser", f"Racer {i}", f"race-pw-{i}") for i in range(4)]
    args_list = _register_args(creds, distinct + same_name)

    ctx = mp.get_context("spawn")
    with ctx.Pool(processes=4) as pool:
        winners = pool.map(app._concurrent_register_worker, args_list)

    users, error = app.load_credentials(creds)
    assert error is None
    expected = {"seed", "raceuser", *(f"user{i}" for i in range(6))}
    assert set(users) == expected

    # All distinct users can log in with their own password.
    settings = isolated_store["settings"]
    for username, _, password in distinct:
        status, user, _ = app.authenticate(
            username=username, password=password, settings=settings
        )
        assert status == app.AUTH_OK and user == username

    # The pre-existing seed user survived the concurrent writes.
    status, user, _ = app.authenticate(
        username="seed", password="seed-pw", settings=settings
    )
    assert status == app.AUTH_OK and user == "seed"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))

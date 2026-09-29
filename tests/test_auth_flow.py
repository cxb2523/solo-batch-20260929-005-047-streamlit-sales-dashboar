"""Auth flow tests:

- refresh keeps the login (signed cookie aligned with keys.py / config.toml)
- duplicate registration keeps the old user and its bcrypt hash
- corrupt credentials degrade to a login prompt instead of crashing
- concurrent registrations never lose updates (file lock + atomic rename)
"""

from __future__ import annotations

import json
import multiprocessing as mp
import time

import pytest

import auth


def _register_worker(cred_path, settings, username, password, queue):
    try:
        auth.register_user(username, password, name=username.title(), path=cred_path)
        queue.put((username, "ok", password))
    except auth.UserExistsError:
        queue.put((username, "exists", None))
    except Exception as exc:  # pragma: no cover - surfaces unexpected races
        queue.put((username, f"error:{exc!r}", None))


def test_refresh_keeps_login(tmp_workspace):
    settings = tmp_workspace["settings"]
    cred = tmp_workspace["cred_path"]
    auth.register_user("pparker", "s3cret!", name="Peter Parker", path=cred)

    store = auth.load_credentials(cred)
    result = auth.authenticate(
        store,
        submitted_username="pparker",
        submitted_password="s3cret!",
        settings=settings,
    )
    assert result.status is True
    assert result.token

    # Simulate a browser refresh: no form submitted, cookie is sent back.
    refreshed = auth.authenticate(
        auth.load_credentials(cred), cookie_token=result.token, settings=settings
    )
    assert refreshed.status is True
    assert refreshed.username == "pparker"
    assert refreshed.name == "Peter Parker"

    # A cookie signed with a different key must not authenticate.
    forged = auth.create_cookie_token("pparker", "a-different-key", 7)
    assert (
        auth.authenticate(
            auth.load_credentials(cred), cookie_token=forged, settings=settings
        ).status
        is None
    )

    # An expired cookie falls back to the login prompt.
    expired = auth.create_cookie_token(
        "pparker", settings["cookie_key"], 7, now=time.time() - 8 * 24 * 3600
    )
    assert (
        auth.authenticate(
            auth.load_credentials(cred), cookie_token=expired, settings=settings
        ).status
        is None
    )


def test_duplicate_registration_keeps_old_user(tmp_workspace):
    cred = tmp_workspace["cred_path"]
    auth.register_user("rmiller", "orig-pass", name="Rebecca Miller", path=cred)
    original_hash = auth.load_credentials(cred)["users"]["rmiller"]["password_hash"]

    with pytest.raises(auth.UserExistsError):
        auth.register_user("RMILLER", "hijack-pass", path=cred)

    store = auth.load_credentials(cred)
    assert set(store["users"]) == {"rmiller"}
    assert store["users"]["rmiller"]["password_hash"] == original_hash

    settings = tmp_workspace["settings"]
    assert (
        auth.authenticate(store, "rmiller", "orig-pass", settings=settings).status
        is True
    )
    assert (
        auth.authenticate(store, "rmiller", "hijack-pass", settings=settings).status
        is False
    )

    raw = cred.read_text(encoding="utf-8")
    assert "orig-pass" not in raw
    assert "hijack-pass" not in raw  # no plaintext ever hits disk


def test_corrupt_credentials_degrade_to_login_prompt(tmp_workspace):
    cred = tmp_workspace["cred_path"]
    auth.ensure_credentials(cred)
    cred.write_text("{ this is not valid json", encoding="utf-8")

    with pytest.raises(auth.CredentialsError):
        auth.load_credentials(cred)

    # Mirrors main() in app.py: catch, show the login prompt, never load data.
    data_loaded = {"flag": False}

    def run_gate():
        try:
            settings = tmp_workspace["settings"]
            credentials = auth.load_credentials(cred)
        except auth.AuthError:
            return None
        result = auth.authenticate(credentials, settings=settings)
        if result.status is True:
            auth.load_data()
            data_loaded["flag"] = True
            return result.username
        return None

    assert run_gate() is None
    assert data_loaded["flag"] is False

    cred.write_text(json.dumps(["not", "a", "store"]), encoding="utf-8")
    with pytest.raises(auth.CredentialsError):
        auth.load_credentials(cred)


def test_missing_credentials_auto_provisioned(tmp_workspace):
    cred = tmp_workspace["cred_path"]
    assert not cred.exists()
    auth.ensure_credentials(cred)
    assert auth.load_credentials(cred) == {"users": {}}


def test_concurrent_registrations_lose_no_updates(tmp_workspace):
    cred = tmp_workspace["cred_path"]
    auth.ensure_credentials(cred)
    settings = tmp_workspace["settings"]

    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    args = [
        ("sameuser", "pw-a"),
        ("sameuser", "pw-b"),
        ("sameuser", "pw-c"),
        ("user_x", "pw-x"),
        ("user_y", "pw-y"),
    ]
    jobs = []
    for user, pw in args:
        proc = ctx.Process(
            target=_register_worker,
            args=(str(cred), settings, user, pw, queue),
        )
        proc.start()
        jobs.append(proc)
    for proc in jobs:
        proc.join(timeout=30)
        assert proc.exitcode == 0

    outcomes = [queue.get() for _ in args]
    sameuser = [(status, pw) for name, status, pw in outcomes if name == "sameuser"]
    ok_results = [pw for status, pw in sameuser if status == "ok"]
    assert len(ok_results) == 1
    assert sum(1 for status, _ in sameuser if status == "exists") == 2
    winner_pw = ok_results[0]

    store = auth.load_credentials(cred)
    assert set(store["users"]) == {"sameuser", "user_x", "user_y"}

    assert (
        auth.authenticate(store, "sameuser", winner_pw, settings=settings).status
        is True
    )
    leftovers = [p.name for p in cred.parent.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []

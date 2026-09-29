"""Shared pytest fixtures: isolated config.toml + credentials.json per test."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import auth  # noqa: E402
import keys  # noqa: E402


@pytest.fixture()
def tmp_workspace(tmp_path, monkeypatch):
    """Point auth paths at a temp copy with its own config.toml and cookie key."""
    streamlit_dir = tmp_path / ".streamlit"
    streamlit_dir.mkdir()
    config_path = streamlit_dir / "config.toml"
    config_path.write_text('[theme]\nfont = "sans serif"\n', encoding="utf-8")

    key = keys.write_cookie_key(config_path)
    cred_path = tmp_path / "credentials.json"

    settings = {
        "cookie_name": "sales_dashboard_auth",
        "cookie_key": key,
        "cookie_expiry_days": 7.0,
        "credentials_file": "credentials.json",
        "credentials_path": cred_path,
    }
    monkeypatch.setattr(auth, "BASE_DIR", tmp_path)
    monkeypatch.setattr(auth, "CONFIG_PATH", config_path)
    return {
        "root": tmp_path,
        "config_path": config_path,
        "cred_path": cred_path,
        "settings": settings,
    }

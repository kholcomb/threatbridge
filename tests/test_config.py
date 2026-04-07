"""Tests for cve_intel.config Settings."""

import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsConfigDict


def _make_settings_no_dotenv(**kwargs):
    """Instantiate Settings without loading .env, so tests are isolated."""
    from cve_intel.config import Settings

    # Subclass to disable .env loading for isolation
    class IsolatedSettings(Settings):
        model_config = SettingsConfigDict(env_file=None)

    return IsolatedSettings(**kwargs)


def test_default_cache_dir_is_not_relative(monkeypatch):
    # Remove CACHE_DIR from env so the default function is used
    monkeypatch.delenv("CACHE_DIR", raising=False)
    s = _make_settings_no_dotenv()
    cache_str = str(s.cache_dir)
    assert not cache_str.startswith("."), (
        f"cache_dir should not be CWD-relative, got: {cache_str}"
    )
    assert "cve-intel" in cache_str, (
        f"cache_dir should contain 'cve-intel', got: {cache_str}"
    )


def test_cache_ttl_validator_rejects_zero(monkeypatch):
    monkeypatch.delenv("CACHE_DIR", raising=False)
    with pytest.raises(ValidationError):
        _make_settings_no_dotenv(cache_ttl_seconds=0)


def test_cache_ttl_validator_rejects_negative(monkeypatch):
    monkeypatch.delenv("CACHE_DIR", raising=False)
    with pytest.raises(ValidationError):
        _make_settings_no_dotenv(cache_ttl_seconds=-1)


def test_cache_dir_env_override(monkeypatch):
    monkeypatch.setenv("CACHE_DIR", "/tmp/test-cache")
    s = _make_settings_no_dotenv()
    assert s.cache_dir == Path("/tmp/test-cache")

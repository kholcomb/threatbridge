import os
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anchor .env lookup to the project root regardless of working directory.
# This matters for the MCP server, which may start from any cwd.
_PROJECT_ROOT = Path(__file__).parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


def _default_cache_dir() -> Path:
    # XDG on Linux, ~/Library/Caches on macOS, %LOCALAPPDATA% on Windows
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "cve-intel"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ENV_FILE), env_file_encoding="utf-8")

    anthropic_api_key: str = ""
    nvd_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"
    cache_dir: Path = _default_cache_dir()
    cache_ttl_seconds: int = 86400
    vulnrichment_cache_ttl: int = 0  # 0 = disabled; set to seconds (e.g. 3600) to cache
    sigmahq_cache_ttl: int = 0       # 0 = disabled; set to seconds (e.g. 3600) to cache
    attack_bundle_path: Path | None = None
    max_tokens: int = 4096

    @field_validator("attack_bundle_path", mode="before")
    @classmethod
    def empty_path_is_none(cls, v: object) -> object:
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @field_validator("cache_ttl_seconds")
    @classmethod
    def cache_ttl_must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("cache_ttl_seconds must be positive")
        return v

    @property
    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def has_nvd_key(self) -> bool:
        return bool(self.nvd_api_key)


settings = Settings()

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    anthropic_api_key: str = ""
    nvd_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"
    cache_dir: Path = Path("./cache")
    cache_ttl_seconds: int = 86400
    attack_bundle_path: Path | None = None
    max_tokens: int = 4096

    @property
    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def has_nvd_key(self) -> bool:
        return bool(self.nvd_api_key)


settings = Settings()

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # env_ignore_empty: a line like "LLM_MODEL=" counts as not set, so the default is used.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    llm_model: str | None = None
    llm_api_key: SecretStr | None = None
    database_url: str = "sqlite:///./data/app.db"
    content_dir: str = "content"
    starter_dir: str = "starter"
    workspaces_dir: str = "workspaces"
    snapshots_dir: str = "snapshots"
    part_time_limit_minutes: int = 25  # CONFIRM after the pilot
    test_timeout_seconds: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()

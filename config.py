from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # env_ignore_empty: a line like "LLM_MODEL=" counts as not set, so the default is used.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True, hide_input_in_errors=True)

    llm_model: str | None = None
    llm_api_key: SecretStr | None = None
    database_url: str = "sqlite:///./data/app.db"
    content_dir: str = "content"
    starter_dir: str = "starter"
    workspaces_dir: str = "workspaces"
    snapshots_dir: str = "snapshots"
    app_env: Literal["development", "production"] = "development"
    frontend_origins: list[str] = [
        "http://localhost:5001", "http://127.0.0.1:5001",
        "http://localhost:5000", "http://127.0.0.1:5000",
    ]
    allowed_hosts: list[str] = ["*"]
    api_docs_enabled: bool = True
    test_timeout_seconds: int = Field(default=60, ge=1, le=300)
    test_runner_url: str | None = None
    test_runner_token: SecretStr | None = None
    pending_session_ttl_seconds: int = Field(default=7200, ge=60)
    max_pending_sessions: int = Field(default=1000, ge=1)

    @model_validator(mode="after")
    def production_settings(self):
        if self.app_env != "production":
            return self
        if not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("Production requires a PostgreSQL DATABASE_URL")
        if not self.llm_model or not self.llm_api_key:
            raise ValueError("Production requires LLM_MODEL and LLM_API_KEY")
        if not self.test_runner_url or not self.test_runner_token:
            raise ValueError("Production requires the isolated TEST_RUNNER_URL and TEST_RUNNER_TOKEN")
        if "*" in self.allowed_hosts or not self.allowed_hosts:
            raise ValueError("Production requires explicit ALLOWED_HOSTS")
        if any(not Path(path).is_absolute() for path in (self.workspaces_dir, self.snapshots_dir)):
            raise ValueError("Production requires absolute workspace and snapshot paths on persistent storage")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

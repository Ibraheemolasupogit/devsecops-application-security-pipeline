"""Application configuration with secure local defaults."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings.

    Defaults are intentionally local and deny broad browser access.
    """

    model_config = SettingsConfigDict(env_prefix="GRAA_", extra="ignore")

    service_name: str = "genomic-research-access-api"
    environment: str = "local"
    cors_allowed_origins: tuple[str, ...] = Field(
        default=("http://localhost:8000", "http://127.0.0.1:8000")
    )
    simulated_reviewer_id: str = "local-approver-001"
    simulated_reviewer_role: str = "approver"


@lru_cache
def get_settings() -> Settings:
    return Settings()

"""Application configuration with secure local defaults."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings.

    Defaults are intentionally local and deny broad browser access.
    """

    model_config = SettingsConfigDict(env_prefix="GRAA_", extra="ignore")

    service_name: str = "genomic-research-access-api"
    environment: str = "local"
    jwt_algorithm: str = "RS256"
    jwt_issuer: str = "https://local.dev/genomic-research-access-api"
    jwt_audience: str = "genomic-research-access-api"
    jwt_public_key_path: Path = Path("tests/fixtures/keys/dev_public_key.pem")
    jwt_clock_skew_seconds: int = 30
    jwt_maximum_lifetime_seconds: int = 900
    expose_api_docs: bool = True
    enable_hsts: bool = False
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    rate_limit_max_subjects: int = 256
    cors_allowed_origins: tuple[str, ...] = Field(
        default=("http://localhost:8000", "http://127.0.0.1:8000")
    )

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if self.jwt_algorithm != "RS256":
            raise ValueError("Only RS256 is supported for local JWT validation.")
        if "*" in self.cors_allowed_origins:
            raise ValueError("Wildcard CORS origins are not permitted.")
        if self.environment != "local" and self.expose_api_docs:
            raise ValueError("API documentation exposure must be disabled outside local mode.")
        if self.environment != "local" and not self.jwt_public_key_path:
            raise ValueError("A JWT public key source is required outside local mode.")
        if self.rate_limit_requests < 1:
            raise ValueError("Rate limit request count must be positive.")
        if self.rate_limit_window_seconds < 1:
            raise ValueError("Rate limit window must be positive.")
        if self.rate_limit_max_subjects < 1:
            raise ValueError("Rate limit subject capacity must be positive.")
        return self

    def load_jwt_public_key(self) -> str:
        return self.jwt_public_key_path.read_text(encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()

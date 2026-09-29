"""Application settings, read from environment variables / the repository .env file.

Secrets (SECRET_KEY, AI_API_KEY, EMBEDDING_API_KEY, DATABASE_URL credentials) are
read only on the server and never sent to the React frontend.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .paths import REPO_ROOT

ProviderName = Literal["anthropic", "openai", "gemini"]

DEV_SECRET_KEY = "dev-only-insecure-secret-change-me"
DEFAULT_DEMO_PASSWORD = "Lumora#Demo2026"

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-4.1-mini",
    "gemini": "gemini-2.5-flash",
}


def _env_files() -> tuple[str, ...]:
    """Load settings from .env and optional .env.secrets."""
    override = os.environ.get("SUPPORTNOVA_ENV_FILE")
    return (override,) if override else (
        str(REPO_ROOT / ".env"),
        str(REPO_ROOT / ".env.secrets"),
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["development", "test", "production"] = "development"
    app_name: str = "SupportNova"
    api_prefix: str = "/api/v1"

    secret_key: SecretStr = SecretStr(DEV_SECRET_KEY)
    access_token_minutes: int = 480
    cookie_secure: bool = False

    database_url: str = (
        "postgresql+psycopg://supportnova:postgres@127.0.0.1:5433/supportnova"
    )
    db_echo: bool = False

    # ---- GenAI ---------------------------------------------------------------

    ai_provider: str = "openai"
    ai_api_key: SecretStr | None = None
    ai_model: str | None = None
    ai_base_url: str | None = None

    ai_timeout_seconds: float = 60.0
    ai_max_retries: int = 2
    ai_temperature: float = 0.1
    ai_max_output_tokens: int = 4096

    ai_effort: str | None = "medium"
    ai_refusal_fallback: bool = True

    # ---- Embeddings / retrieval ---------------------------------------------

    embedding_provider: Literal["local", "openai", "gemini"] = "local"
    embedding_model: str | None = None
    embedding_api_key: SecretStr | None = None

    vector_database_url: str | None = None
    retrieval_top_k: int = 10

    redis_url: str | None = None

    # ---- Web / security ------------------------------------------------------

    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://support-nova-git-main-usama-s-projects5.vercel.app",
        ]
    )

    rate_limit_per_minute: int = 240
    login_rate_limit_per_minute: int = 20
    max_upload_mb: int = 15
    max_attachment_mb: int = 5

    serve_frontend: bool = True

    # ---- Complaint processing -----------------------------------------------

    duplicate_window_hours: int = 24
    reject_exact_duplicates: bool = True
    near_duplicate_threshold: float = 0.86
    repeat_similarity_threshold: float = 0.30

    background_workers: int = 2
    batch_workers: int = 4
    sla_monitor_interval_seconds: int = 60

    # ---- First-run setup -----------------------------------------------------

    auto_migrate: bool = True
    auto_seed: bool = True
    seed_dataset_on_startup: bool = True
    seed_demo_users: bool = True
    seed_simulate_lifecycle: bool = True

    demo_password: SecretStr = SecretStr(DEFAULT_DEMO_PASSWORD)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.strip().startswith("["):
                return json.loads(value)

            return [
                v.strip()
                for v in value.split(",")
                if v.strip()
            ]

        return value

    @field_validator(
        "ai_api_key",
        "ai_model",
        "ai_base_url",
        "ai_effort",
        "embedding_model",
        "embedding_api_key",
        "vector_database_url",
        "redis_url",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None

        return value

    @field_validator("ai_provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        name = (value or "").strip().lower()

        if name not in (
            "openai",
            "anthropic",
            "gemini",
            "real",
        ):
            raise ValueError(
                "AI_PROVIDER must be openai, anthropic, gemini or real"
            )

        return name

    @field_validator(
        "secret_key",
        "demo_password",
        mode="before",
    )
    @classmethod
    def _blank_secret_is_default(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:

        if isinstance(value, str) and not value.strip():
            if info.field_name == "secret_key":
                return DEV_SECRET_KEY

            return DEFAULT_DEMO_PASSWORD

        return value

    @field_validator("database_url", mode="before")
    @classmethod
    def _psycopg_driver(cls, value: object) -> object:

        if isinstance(value, str):
            for prefix in (
                "postgres://",
                "postgresql://",
            ):
                if value.startswith(prefix):
                    return (
                        "postgresql+psycopg://"
                        + value[len(prefix):]
                    )

        return value

    @model_validator(mode="after")
    def _production_guard(self) -> Settings:

        if self.app_env == "production":
            key = self.secret_key.get_secret_value()

            if key == DEV_SECRET_KEY or len(key) < 32:
                raise ValueError(
                    "APP_ENV=production requires SECRET_KEY: "
                    "a random value of at least 32 characters "
                    '(for example: python -c "import secrets; '
                    'print(secrets.token_urlsafe(48))").'
                )

        return self

    # ---- derived -------------------------------------------------------------

    @property
    def resolved_provider(self) -> ProviderName:

        name = (self.ai_provider or "openai").strip().lower()

        if name in (
            "anthropic",
            "openai",
            "gemini",
        ):
            return name  # type: ignore[return-value]

        key = (
            self.ai_api_key.get_secret_value()
            if self.ai_api_key
            else ""
        )

        model = (self.ai_model or "").lower()

        if key.startswith("sk-ant-") or model.startswith("claude"):
            return "anthropic"

        if key.startswith("AIza") or model.startswith("gemini"):
            return "gemini"

        return "openai"

    @property
    def resolved_model(self) -> str:
        return (
            self.ai_model
            or DEFAULT_MODELS[self.resolved_provider]
        )

    @property
    def ai_configured(self) -> bool:
        return bool(
            self.ai_api_key
            and self.ai_api_key.get_secret_value()
        )

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

import os
from dataclasses import dataclass
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = "Bayora"
    database_url: str = os.getenv("BAYORA_DATABASE_URL", "sqlite:///./bayora.db")
    cors_origins: str = os.getenv("BAYORA_CORS_ORIGINS", "http://localhost:5173")
    request_timeout_seconds: int = int(os.getenv("BAYORA_REQUEST_TIMEOUT_SECONDS", "20"))
    max_upload_bytes: int = int(os.getenv("BAYORA_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
    rate_limit_requests: int = int(os.getenv("BAYORA_RATE_LIMIT_REQUESTS", "20"))
    rate_limit_window_seconds: int = int(os.getenv("BAYORA_RATE_LIMIT_WINDOW_SECONDS", "60"))
    auth_secret: str = os.getenv("BAYORA_AUTH_SECRET", "bayora-local-development-secret-change-before-deploy")
    demo_password: str = os.getenv("BAYORA_DEMO_PASSWORD", "bayora-demo")
    allow_demo_role_header: bool = os.getenv("BAYORA_ALLOW_DEMO_ROLE_HEADER", "true").lower() in {"1", "true", "yes"}

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

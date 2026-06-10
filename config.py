import os
from datetime import timedelta


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///naf_messaging.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MESSAGE_ENCRYPTION_KEY = os.getenv("MESSAGE_ENCRYPTION_KEY")
    WTF_CSRF_ENABLED = env_bool("WTF_CSRF_ENABLED", True)
    WTF_CSRF_TIME_LIMIT = int(os.getenv("WTF_CSRF_TIME_LIMIT", "7200"))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")))

    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "300 per hour")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(25 * 1024 * 1024)))


def validate_required_config(app):
    missing = []
    if not app.config.get("SECRET_KEY") or app.config.get("SECRET_KEY") == "dev-change-me":
        missing.append("SECRET_KEY")
    if not app.config.get("MESSAGE_ENCRYPTION_KEY"):
        missing.append("MESSAGE_ENCRYPTION_KEY")
    if missing:
        raise RuntimeError(
            "NMS secure startup refused. Missing/weak required setting(s): "
            + ", ".join(missing)
            + ". Copy .env.example to .env or run scripts/bootstrap_env.py, then restart."
        )

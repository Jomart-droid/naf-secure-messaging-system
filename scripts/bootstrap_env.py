from pathlib import Path
from secrets import token_urlsafe
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"
EXAMPLE = ROOT / ".env.example"

values = {}
if EXAMPLE.exists():
    for line in EXAMPLE.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            values[k] = v
if ENV.exists():
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            values[k] = v

values["SECRET_KEY"] = values.get("SECRET_KEY") or token_urlsafe(48)
values["MESSAGE_ENCRYPTION_KEY"] = values.get("MESSAGE_ENCRYPTION_KEY") or Fernet.generate_key().decode()
values.setdefault("DATABASE_URL", "sqlite:///naf_messaging.db")
values.setdefault("HOST", "0.0.0.0")
values.setdefault("PORT", "5000")
values.setdefault("FLASK_DEBUG", "1")
values.setdefault("SESSION_TIMEOUT_MINUTES", "30")
values.setdefault("SESSION_COOKIE_SECURE", "0")
values.setdefault("WTF_CSRF_ENABLED", "1")

ordered = ["SECRET_KEY", "MESSAGE_ENCRYPTION_KEY", "DATABASE_URL", "HOST", "PORT", "FLASK_DEBUG", "APP_ENV", "SESSION_TIMEOUT_MINUTES", "SESSION_COOKIE_SECURE", "SESSION_COOKIE_SAMESITE", "WTF_CSRF_ENABLED", "WTF_CSRF_TIME_LIMIT", "RATELIMIT_DEFAULT", "RATELIMIT_STORAGE_URI", "MAX_CONTENT_LENGTH", "SOCKETIO_CORS_ORIGINS"]
lines = ["# Auto-generated local NMS environment. Do not share this file.\n"]
for k in ordered:
    if k in values:
        lines.append(f"{k}={values[k]}")
for k in sorted(set(values) - set(ordered)):
    lines.append(f"{k}={values[k]}")
ENV.write_text("\n".join(lines).strip() + "\n")
print(f"Created/updated {ENV}")

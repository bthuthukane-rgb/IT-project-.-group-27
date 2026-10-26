"""Central configuration. Override anything with environment variables or a .env file."""

import os
import secrets
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _load_env():
    f = BASE / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            line = line.strip()

            if (
                line
                and not line.startswith("#")
                and "=" in line
            ):
                k, v = line.split("=", 1)
                os.environ.setdefault(
                    k.strip(),
                    v.strip().strip("\"'")
                )


_load_env()

INSTANCE = BASE / "instance"
INSTANCE.mkdir(exist_ok=True)


def _secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]

    f = INSTANCE / "secret_key"

    if not f.exists():
        f.write_text(secrets.token_hex(32))

        try:
            f.chmod(0o600)
        except OSError:
            pass

    return f.read_text().strip()


def _bool(name, default=False):
    return os.environ.get(
        name,
        str(int(default))
    ).lower() in ("1", "true", "yes")


CATEGORIES = [
    "Painting",
    "Cleaning",
    "Gardening",
    "Basic Repairs",
    "Plumbing",
    "Electrical",
    "Carpentry",
    "Laundry & Ironing",
    "Moving Help",
]


class Config:
    # Security
    SECRET_KEY = _secret()

    # Database
    DATABASE = os.environ.get(
        "DATABASE",
        str(INSTANCE / "marketplace.db")
    )

    # Site URL
    BASE_URL = os.environ.get(
        "BASE_URL",
        "http://127.0.0.1:5000"
    ).rstrip("/")

    # Sessions / Cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("HTTPS")
    PERMANENT_SESSION_LIFETIME = 60 * 30
    MAX_CONTENT_LENGTH = 256 * 1024

    # =====================================
    # SMTP (GMAIL)
    # =====================================

    SMTP_HOST = os.environ.get(
        "SMTP_HOST",
        "smtp.gmail.com"
    )

    SMTP_PORT = int(
        os.environ.get(
            "SMTP_PORT",
            "587"
        )
    )

    SMTP_USER = os.environ.get(
        "SMTP_USER",
        "yourgmail@gmail.com"
    )

    SMTP_PASSWORD = os.environ.get(
        "SMTP_PASSWORD",
        ""
    )

    SMTP_TLS = _bool(
        "SMTP_TLS",
        True
    )

    SMTP_SSL = _bool(
        "SMTP_SSL",
        False
    )

    MAIL_FROM = os.environ.get(
        "MAIL_FROM",
        f"Household Skills Marketplace <{SMTP_USER}>"
    )

    # =====================================
    # IMAP (OPTIONAL FOR INCOMING MAIL)
    # =====================================

    IMAP_HOST = os.environ.get(
        "IMAP_HOST",
        "imap.gmail.com"
    )

    IMAP_USER = os.environ.get(
        "IMAP_USER",
        SMTP_USER
    )

    IMAP_PASSWORD = os.environ.get(
        "IMAP_PASSWORD",
        SMTP_PASSWORD
    )

    # Development helper
    DEV_ECHO = _bool("DEV_ECHO", False)

    # Backups
    BACKUP_DIR = os.environ.get(
        "BACKUP_DIR",
        str(BASE / "backups")
    )

    BACKUP_KEEP = int(
        os.environ.get(
            "BACKUP_KEEP",
            "14"
        )
    )

    BACKUP_INTERVAL_HOURS = float(
        os.environ.get(
            "BACKUP_INTERVAL_HOURS",
            "24"
        )
    )

    # Admin bootstrap
    ADMIN_EMAIL = os.environ.get(
        "ADMIN_EMAIL",
        "admin@example.com"
    )

    ADMIN_PASSWORD = os.environ.get(
        "ADMIN_PASSWORD",
        ""
    )

    THROTTLE = True
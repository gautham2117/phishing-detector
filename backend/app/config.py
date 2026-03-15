# config.py
# Centralized configuration using environment variables.
# We use python-dotenv to load the .env file automatically.

import os
from dotenv import load_dotenv

# Load the .env file from the project root.
# This makes all key=value pairs in .env available via os.environ.
load_dotenv()

class Config:
    """Base configuration class. All settings are read from environment variables."""

    # Flask secret key — used to sign session cookies.
    # NEVER hardcode this. Always load from environment.
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

    # SQLAlchemy database URI.
    # Default: SQLite file in the /database/ folder.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///database/phishing_detector.db"
    )

    # Disable SQLAlchemy's modification tracking (saves memory).
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # FastAPI service URL — Flask will proxy scan requests here.
    FASTAPI_BASE_URL = os.environ.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")

    # Redis URL (optional for local dev — used for task queue concept).
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # Optional external API keys
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")


class DevelopmentConfig(Config):
    """Development-specific config: debug mode on, verbose logging."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production config: debug off, use PostgreSQL."""
    DEBUG = False
    TESTING = False
    # In production, DATABASE_URL should point to PostgreSQL.
    # Example: postgresql://user:password@localhost/phishing_db


# Map string names to config classes.
# We use this in the app factory: app.config.from_object(config_map[env])
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
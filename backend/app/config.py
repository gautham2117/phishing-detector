# config.py
# Centralized configuration using environment variables.
# All file paths are built as absolute paths from this file's
# location so they work regardless of which directory you run
# the server from.

import os
from dotenv import load_dotenv

# Load .env from the project root (two levels above this file)
# __file__ = .../phishing-detector/backend/app/config.py
# app_dir      = .../phishing-detector/backend/app/
# backend_dir  = .../phishing-detector/backend/
# project_root = .../phishing-detector/
_app_dir      = os.path.dirname(os.path.abspath(__file__))
_backend_dir  = os.path.dirname(_app_dir)
_project_root = os.path.dirname(_backend_dir)

# Load the .env file from project root
load_dotenv(os.path.join(_project_root, ".env"))

# Build the absolute path to the database folder and file
_database_dir  = os.path.join(_project_root, "database")
_database_file = os.path.join(_database_dir, "phishing_detector.db")

# Create the database/ directory right now if it doesn't exist.
# This is the key fix — SQLite cannot create the file if the
# parent directory doesn't exist.
os.makedirs(_database_dir, exist_ok=True)


class Config:
    """Base configuration — all settings read from environment variables."""

    # Flask secret key — signs session cookies
    SECRET_KEY = os.environ.get(
        "FLASK_SECRET_KEY",
        "dev-secret-key-change-in-production"
    )

    # SQLite database URI using absolute path
    # sqlite:/// (3 slashes) + absolute path = correct on all platforms
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{_database_file}"
    )

    # Disable SQLAlchemy modification tracking (saves memory)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # FastAPI microservice URL
    FASTAPI_BASE_URL = os.environ.get(
        "FASTAPI_BASE_URL",
        "http://127.0.0.1:8001"
    )

    # Redis URL (optional for local dev)
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # Optional external API keys
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "3979298a0130dc78c7a03a77ec7dd89cacaff5ddaf90e25c2b002059ee74b875")
    IPINFO_TOKEN       = os.environ.get("IPINFO_TOKEN", "661042d7109519")


class DevelopmentConfig(Config):
    """Development config — debug on, verbose logging."""
    DEBUG   = True
    TESTING = False


class ProductionConfig(Config):
    """
    Production config — debug off.
    Set DATABASE_URL in .env to point to PostgreSQL:
    DATABASE_URL=postgresql://user:password@localhost/phishing_db
    """
    DEBUG   = False
    TESTING = False


class TestingConfig(Config):
    """Testing config — uses a separate in-memory SQLite database."""
    TESTING = True
    DEBUG   = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


# Map string names to config classes.
# Used in create_app(): app.config.from_object(config_map[env])
config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig,
    "default":     DevelopmentConfig,
}
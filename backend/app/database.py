# database.py
# SQLAlchemy database instance.
# We create db here (not in __init__.py) to avoid circular imports.
# All models import db from here.

from flask_sqlalchemy import SQLAlchemy

# This single db object is shared across all model files.
# It gets bound to the Flask app inside create_app() via db.init_app(app).
db = SQLAlchemy()
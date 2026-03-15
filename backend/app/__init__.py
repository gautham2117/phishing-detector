# __init__.py
# The Flask application factory.
# Using a factory function (create_app) instead of a global app object
# makes testing easier and avoids circular import issues.

from flask import Flask
from .config import config_map
from .database import db
import os


def create_app(config_name: str = "default") -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_name: Which config class to use ('development' or 'production').

    Returns:
        A configured Flask application instance.
    """

    # Create the Flask app, pointing it to the frontend/templates and
    # frontend/static directories (they live outside the backend/app folder).
    app = Flask(
        __name__,
        template_folder="../../frontend/templates",
        static_folder="../../frontend/static"
    )

    # Load the configuration class (DevelopmentConfig or ProductionConfig).
    app.config.from_object(config_map[config_name])

    # Initialize the database with this app instance.
    # db.init_app() binds the SQLAlchemy instance to the app.
    db.init_app(app)

    # Register all Flask Blueprints (one per dashboard module).
    # Each Blueprint handles routes for one module page.
    from .routes.dashboard     import dashboard_bp
    from .routes.email_scan    import email_scan_bp
    from .routes.url_intel     import url_intel_bp
    from .routes.risk_score    import risk_score_bp
    from .routes.alerts        import alerts_bp
    from .routes.model_mgmt    import model_mgmt_bp
    from .routes.live_monitor  import live_monitor_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(email_scan_bp,   url_prefix="/email")
    app.register_blueprint(url_intel_bp,    url_prefix="/url")
    app.register_blueprint(risk_score_bp,   url_prefix="/risk")
    app.register_blueprint(alerts_bp,       url_prefix="/alerts")
    app.register_blueprint(model_mgmt_bp,   url_prefix="/models")
    app.register_blueprint(live_monitor_bp, url_prefix="/monitor")

    # Create all database tables if they don't exist yet.
    # This replaces running manual SQL migrations in development.
    with app.app_context():
        db.create_all()

    return app
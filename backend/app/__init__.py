# backend/app/__init__.py
# Flask application factory.

import os
import logging
from flask import Flask
from backend.app.config import config_map
from backend.app.database import db

logger = logging.getLogger(__name__)


def create_app(config_name: str = "default") -> Flask:
    """
    Create and configure the Flask application instance.

    Args:
        config_name: "development", "production", or "testing".

    Returns:
        A fully configured Flask app.
    """

    # ── Resolve template and static folder absolute paths ─────────────────
    _app_dir      = os.path.dirname(os.path.abspath(__file__))
    _backend_dir  = os.path.dirname(_app_dir)
    _project_root = os.path.dirname(_backend_dir)

    template_folder = os.path.join(_project_root, "frontend", "templates")
    static_folder   = os.path.join(_project_root, "frontend", "static")

    # ── Create Flask app ───────────────────────────────────────────────────
    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder
    )

    # ── Load configuration ─────────────────────────────────────────────────
    app.config.from_object(
        config_map.get(config_name, config_map["default"])
    )

    # ── Initialise SQLAlchemy ──────────────────────────────────────────────
    db.init_app(app)

    # ── Register Blueprints ────────────────────────────────────────────────
    _register_blueprints(app)

    # ── Create database tables ─────────────────────────────────────────────
    _setup_database(app)

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Blueprint registration
# ─────────────────────────────────────────────────────────────────────────────

def _register_blueprints(app: Flask) -> None:
    """Register all Flask blueprints — one per dashboard module."""

    # ── Always-present blueprints (Phases 1–3 are fully built) ────────────

    from backend.app.routes.dashboard    import dashboard_bp
    from backend.app.routes.email_scan   import email_scan_bp
    from backend.app.routes.url_intel    import url_intel_bp
    from backend.app.routes.network_scan import network_scan_bp
    from backend.app.routes.attachment import bp as attachment_bp
    
    app.register_blueprint(attachment_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(email_scan_bp,   url_prefix="/email")
    app.register_blueprint(url_intel_bp,    url_prefix="/url")
    app.register_blueprint(network_scan_bp, url_prefix="/network")

    # ── Placeholder blueprints (phases not yet built) ──────────────────────
    # Each entry: (import_path, bp_variable_name, url_prefix, display_title, phase)

    optional_blueprints = [
        ("backend.app.routes.detection_rules",  "rules_bp",        "/rules",          "Detection Rules",    "Phase 4"),
        ("backend.app.routes.ml_classifier",    "ml_bp",           "/ml/classifier",  "ML Classifier",      "Phase 5"),
        ("backend.app.routes.attachment",       "attachment_bp",   "/attachments",    "Attachment Analysis","Phase 6"),
        ("backend.app.routes.image_analysis",   "image_bp",        "/image/analysis", "Image Analysis",     "Phase 7"),
        ("backend.app.routes.ai_detection",     "ai_bp",           "/ai/detection",   "AI Detection",       "Phase 8"),
        ("backend.app.routes.platform_monitor", "platform_bp",     "/platform",       "Platform Monitor",   "Phase 9"),
        ("backend.app.routes.risk_score",       "risk_score_bp",   "/risk",           "Risk Score",         "Phase 10"),
        ("backend.app.routes.live_monitor",     "live_monitor_bp", "/monitor",        "Live Monitor",       "Phase 11"),
        ("backend.app.routes.model_mgmt",       "model_mgmt_bp",   "/models",         "Model Management",   "Phase 12"),
        ("backend.app.routes.alerts",           "alerts_bp",       "/alerts",         "Alerts & Audit",     "Phase 13"),
        ("backend.app.routes.extension",        "extension_bp",    "/extension",      "Extension",          "Phase 14"),
        ("backend.app.routes.architecture",     "architecture_bp", "/architecture",   "System Architecture","Phase 15"),
        ("backend.app.routes.threat_explain",   "threat_bp",       "/threat/explain", "Threat Explanation", "Phase 16"),
    ]

    for module_path, bp_name, url_prefix, title, phase in optional_blueprints:
        try:
            import importlib
            module = importlib.import_module(module_path)
            bp     = getattr(module, bp_name)
            app.register_blueprint(bp, url_prefix=url_prefix
                                   if not hasattr(bp, 'url_prefix') else None)
            logger.debug(f"Registered blueprint: {bp_name}")
        except (ImportError, AttributeError):
            # Route file doesn't exist yet — register a placeholder page
            _register_placeholder(app, bp_name, url_prefix, title, phase)


# ─────────────────────────────────────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────────────────────────────────────

def _setup_database(app: Flask) -> None:
    """
    Create all database tables inside the app context.
    The database/ directory is guaranteed to exist because
    config.py calls os.makedirs() when it is imported.
    """
    with app.app_context():
        try:
            # Import all models so SQLAlchemy registers them
            # before create_all() is called.
            import backend.app.models  # noqa: F401

            db.create_all()
            logger.info("Database tables created / verified successfully.")

        except Exception as e:
            # Print a clear human-readable error instead of a long traceback
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "unknown")
            logger.error(
                f"\n{'='*60}\n"
                f"DATABASE ERROR: Cannot create tables.\n"
                f"URI: {db_uri}\n"
                f"Reason: {e}\n"
                f"\nFix: make sure the 'database/' folder exists in your\n"
                f"project root and that you have write permission to it.\n"
                f"Run: mkdir database\n"
                f"{'='*60}\n"
            )
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Placeholder blueprint helper
# ─────────────────────────────────────────────────────────────────────────────

def _register_placeholder(app: Flask, name: str, url: str,
                           title: str, phase: str) -> None:
    """
    Register a minimal 'coming soon' blueprint for any module route
    file that hasn't been created yet.
    """
    from flask import Blueprint

    bp = Blueprint(f"placeholder_{name}", __name__)

    def _make_view(t, p):
        def view():
            return (
                f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{t}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f1117; color: #e6edf3;
      display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      min-height: 100vh; margin: 0; gap: 12px;
    }}
    h1  {{ font-size: 20px; margin: 0; }}
    p   {{ color: #8b949e; font-size: 14px; margin: 0; }}
    a   {{ color: #388bfd; text-decoration: none; font-size: 13px; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{
      background: rgba(56,139,253,0.15);
      border: 1px solid rgba(56,139,253,0.30);
      color: #388bfd; border-radius: 6px;
      padding: 5px 14px; font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="badge">{p} — not yet built</div>
  <h1>{t}</h1>
  <p>This module will be available once {p} is completed.</p>
  <a href="/">← Back to Overview</a>
</body>
</html>""",
                200,
                {"Content-Type": "text/html"}
            )
        return view

    bp.add_url_rule(url, endpoint=f"{name}_index",
                    view_func=_make_view(title, phase))
    app.register_blueprint(bp)
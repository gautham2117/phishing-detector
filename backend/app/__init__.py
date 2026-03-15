# backend/app/__init__.py
# Flask application factory — complete corrected version.
#
# KEY FIX: No url_prefix on ANY blueprint registration.
#
# Why? Every route file already defines the FULL path in its decorator.
# Examples:
#   email_scan.py  -> @email_scan_bp.route("/email/scan")
#   url_intel.py   -> @url_intel_bp.route("/url/intel")
#   network_scan.py-> @network_scan_bp.route("/network/scan")
#
# If we also add url_prefix="/email" here, Flask combines them:
#   /email  +  /email/scan  =  /email/email/scan  ->  404
#
# The fix is simple: register every blueprint with NO url_prefix.

import os
import logging
import importlib
from flask import Flask
from backend.app.config import config_map
from backend.app.database import db

logger = logging.getLogger(__name__)


def create_app(config_name: str = "default") -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_name: "development", "production", or "testing"

    Returns:
        Fully configured Flask app with all blueprints registered
        and all database tables created.
    """

    # ── Resolve absolute paths ─────────────────────────────────────────────
    # __file__ = .../phishing-detector/backend/app/__init__.py
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

    # ── Register all blueprints ────────────────────────────────────────────
    _register_blueprints(app)

    # ── Create database tables ─────────────────────────────────────────────
    _setup_database(app)

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Blueprint registration
# ─────────────────────────────────────────────────────────────────────────────

def _register_blueprints(app: Flask) -> None:
    """
    Register all Flask blueprints with NO url_prefix.

    Every route file defines its own complete URL path in its decorator,
    so no prefix is needed or wanted here.

    Phases 1-6: imported directly — these files must exist.
    Phases 7-16: wrapped in try/except — show placeholder if file missing.
    """

    # ── Phase 0 — Overview dashboard ──────────────────────────────────────
    # Routes: /   and   /dashboard/stats
    from backend.app.routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    # ── Phase 1 — Email Scan ───────────────────────────────────────────────
    # Routes: /email/scan   /email/submit   /email/history
    from backend.app.routes.email_scan import email_scan_bp
    app.register_blueprint(email_scan_bp)

    # ── Phase 2 — URL Intelligence ─────────────────────────────────────────
    # Routes: /url/intel   /url/submit   /url/history   /url/detail/<id>
    from backend.app.routes.url_intel import url_intel_bp
    app.register_blueprint(url_intel_bp)

    # ── Phase 3 — Network Scan ─────────────────────────────────────────────
    # Routes: /network/scan   /network/submit   /network/history
    from backend.app.routes.network_scan import network_scan_bp
    app.register_blueprint(network_scan_bp)

    # ── Phase 4 — Detection Rules ──────────────────────────────────────────
    # Routes: /rules   /rules/scan/url   /rules/scan/email   /rules/list
    from backend.app.routes.detection_rules import rules_bp
    app.register_blueprint(rules_bp)

    # ── Phase 5 — ML Classifier ────────────────────────────────────────────
    # Routes: /ml/classifier   /ml/scan   /ml/scan/batch
    from backend.app.routes.ml_classifier import ml_bp
    app.register_blueprint(ml_bp)

    # ── Phase 6 — Attachment Analysis ─────────────────────────────────────
    # Routes: /attachments   /attachments/submit   /attachments/history
    from backend.app.routes.attachment import attachment_bp
    app.register_blueprint(attachment_bp)

    # ── Phases 7-16 — Optional blueprints ─────────────────────────────────
    # Format: (module_path, bp_variable_name, placeholder_url, title, phase)
    #
    # placeholder_url is ONLY used when the route file doesn't exist yet
    # and we need to register a "coming soon" page at that URL.
    # When the real route file exists, it defines its own URL — no prefix.

    optional_blueprints = [
        (
            "backend.app.routes.image_analysis",
            "image_bp",
            "/image/analysis",
            "Image Analysis",
            "Phase 7"
        ),
        (
            "backend.app.routes.ai_detection",
            "ai_bp",
            "/ai/detection",
            "AI Detection",
            "Phase 8"
        ),
        (
            "backend.app.routes.platform_monitor",
            "platform_bp",
            "/platform",
            "Platform Monitor",
            "Phase 9"
        ),
        (
            "backend.app.routes.risk_score",
            "risk_score_bp",
            "/risk",
            "Risk Score",
            "Phase 10"
        ),
        (
            "backend.app.routes.live_monitor",
            "live_monitor_bp",
            "/monitor",
            "Live Monitor",
            "Phase 11"
        ),
        (
            "backend.app.routes.model_mgmt",
            "model_mgmt_bp",
            "/models",
            "Model Management",
            "Phase 12"
        ),
        (
            "backend.app.routes.alerts",
            "alerts_bp",
            "/alerts",
            "Alerts & Audit",
            "Phase 13"
        ),
        (
            "backend.app.routes.extension",
            "extension_bp",
            "/extension",
            "Extension",
            "Phase 14"
        ),
        (
            "backend.app.routes.architecture",
            "architecture_bp",
            "/architecture",
            "System Architecture",
            "Phase 15"
        ),
        (
            "backend.app.routes.threat_explain",
            "threat_bp",
            "/threat/explain",
            "Threat Explanation",
            "Phase 16"
        ),
    ]

    for module_path, bp_name, placeholder_url, title, phase in optional_blueprints:
        try:
            # Try to import the real route file
            module = importlib.import_module(module_path)
            bp     = getattr(module, bp_name)

            # Register with NO url_prefix — the route file has full paths
            app.register_blueprint(bp)
            logger.debug(f"Registered blueprint: {bp_name}")

        except (ImportError, AttributeError):
            # Route file doesn't exist yet — register a placeholder page
            # at the expected URL so the sidebar link doesn't 404
            _register_placeholder(
                app,
                name=bp_name,
                url=placeholder_url,
                title=title,
                phase=phase
            )
            logger.debug(
                f"Placeholder registered for {bp_name} ({phase} not yet built)"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────────────────────────────────────

def _setup_database(app: Flask) -> None:
    """
    Create all database tables inside the app context.
    config.py guarantees the database/ directory exists before this runs.
    """
    with app.app_context():
        try:
            # Import all models so SQLAlchemy registers every table
            # before create_all() is called.
            import backend.app.models  # noqa: F401

            db.create_all()
            logger.info("Database tables created / verified.")

        except Exception as e:
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "unknown")
            logger.error(
                f"\n{'='*60}\n"
                f"DATABASE ERROR: Cannot create tables.\n"
                f"URI: {db_uri}\n"
                f"Reason: {e}\n"
                f"Fix: ensure the 'database/' folder exists in the project root.\n"
                f"Run: mkdir database\n"
                f"{'='*60}\n"
            )
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Placeholder blueprint helper
# ─────────────────────────────────────────────────────────────────────────────

def _register_placeholder(
    app: Flask,
    name: str,
    url: str,
    title: str,
    phase: str
) -> None:
    """
    Register a minimal 'coming soon' blueprint for any module route
    file that hasn't been created yet.

    This is only used when the real route file does not exist.
    Once you create the real route file, this placeholder is
    automatically bypassed by the try/except in _register_blueprints().
    """
    from flask import Blueprint

    # Use a unique name to avoid blueprint name conflicts
    bp = Blueprint(f"placeholder_{name}", __name__)

    def _make_view(t: str, p: str):
        """
        Closure that captures title and phase for the placeholder page.
        Returns a view function — not the HTML directly.
        """
        def view():
            return (
                f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{t}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont,
                   "Segoe UI", sans-serif;
      background: #0f1117;
      color: #e6edf3;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      gap: 14px;
    }}
    h1  {{ font-size: 20px; margin: 0; }}
    p   {{ color: #8b949e; font-size: 14px; margin: 0; }}
    a   {{ color: #388bfd; text-decoration: none; font-size: 13px; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{
      background: rgba(56,139,253,0.15);
      border: 1px solid rgba(56,139,253,0.30);
      color: #388bfd;
      border-radius: 6px;
      padding: 5px 16px;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="badge">{p} — not yet built</div>
  <h1>{t}</h1>
  <p>This module will be available once {p} is completed.</p>
  <a href="/">&#8592; Back to Overview</a>
</body>
</html>""",
                200,
                {"Content-Type": "text/html"}
            )
        return view

    bp.add_url_rule(
        url,
        endpoint=f"{name}_index",
        view_func=_make_view(title, phase)
    )
    app.register_blueprint(bp)
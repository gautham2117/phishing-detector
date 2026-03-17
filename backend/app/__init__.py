# backend/app/__init__.py
# Flask application factory — complete corrected version.
#
# KEY FIX: No url_prefix on ANY blueprint registration.
# KEY FIX 2: Context processor injects sidebar, role, role_label, role_icon
#            into EVERY template automatically — routes never pass these manually.

import os
import logging
import importlib
from flask import Flask, session
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

    # ── Context processor — injects sidebar/role into EVERY template ───────
    # This is the single source of truth for sidebar and role data.
    # Routes MUST NOT pass these values manually.
    @app.context_processor
    def inject_globals():
        from backend.app.routes.dashboard import get_sidebar_config, ROLES
        role     = session.get("role", "")
        role_cfg = ROLES.get(role, {})
        return {
            "sidebar":    get_sidebar_config(),
            "role":       role,
            "role_label": role_cfg.get("label", ""),
            "role_icon":  role_cfg.get("icon",  ""),
        }

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
    """

    # ── Phase 0 — Overview dashboard ──────────────────────────────────────
    from backend.app.routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    # ── Phase 1 — Email Scan ───────────────────────────────────────────────
    from backend.app.routes.email_scan import email_scan_bp
    app.register_blueprint(email_scan_bp)

    # ── Phase 2 — URL Intelligence ─────────────────────────────────────────
    from backend.app.routes.url_intel import url_intel_bp
    app.register_blueprint(url_intel_bp)

    # ── Phase 3 — Network Scan ─────────────────────────────────────────────
    from backend.app.routes.network_scan import network_scan_bp
    app.register_blueprint(network_scan_bp)

    # ── Phase 4 — Detection Rules ──────────────────────────────────────────
    from backend.app.routes.detection_rules import rules_bp
    app.register_blueprint(rules_bp)

    # ── Phase 5 — ML Classifier ────────────────────────────────────────────
    from backend.app.routes.ml_classifier import ml_bp
    app.register_blueprint(ml_bp)

    # ── Phase 6 — Attachment Analysis ─────────────────────────────────────
    from backend.app.routes.attachment import attachment_bp
    app.register_blueprint(attachment_bp)

    # ── Phases 7-16 — Optional blueprints ─────────────────────────────────
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
            "backend.app.routes.model_mgmt",
            "model_mgmt_bp",
            "/models",
            "Model _Management",
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
            module = importlib.import_module(module_path)
            bp     = getattr(module, bp_name)
            app.register_blueprint(bp)
            logger.debug(f"Registered blueprint: {bp_name}")

        except (ImportError, AttributeError):
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
    with app.app_context():
        try:
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
    from flask import Blueprint

    bp = Blueprint(f"placeholder_{name}", __name__)

    def _make_view(t: str, p: str):
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
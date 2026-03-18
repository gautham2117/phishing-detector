# backend/app/__init__.py
# Flask application factory — fully corrected for RBAC.
#
# KEY RULES (never violate):
#   1. Blueprints define their own url_prefix in their constructor.
#      app.register_blueprint() is ALWAYS called with NO url_prefix argument.
#   2. get_sidebar_config(role) lives here — never imported from a route file.
#   3. Context processor injects sidebar, role, role_label, role_icon into
#      EVERY template. Routes MUST NOT pass these manually.
#   4. get_sidebar_config() must ALWAYS be called with (role) — never ()
#      and never passed as a function reference.
#   5. SECRET_KEY must exist in Flask config or sessions silently break.
#   6. model_mgmt_bp and architecture_bp are REQUIRED blueprints — they are
#      not optional. A failed import must raise immediately, not fall back
#      to a placeholder that skips @role_required enforcement.

import os
import logging
import importlib

from flask import Flask, render_template, session
from backend.app.config import config_map
from backend.app.database import db

logger = logging.getLogger(__name__)


# ── Role metadata — single source of truth ─────────────────────────────────────

_ROLES = {
    "visitor": {"label": "Visitor", "icon": "eye"},
    "analyst": {"label": "Analyst", "icon": "search"},
    "admin":   {"label": "Admin",   "icon": "shield"},
}

_DEFAULT_ROLE = "visitor"


# ── Sidebar config — role-filtered ─────────────────────────────────────────────

def get_sidebar_config(role: str = "visitor") -> list:
    """
    Return sidebar navigation items visible to the given role.

    Access matrix:
        visitor  → dashboard only
        analyst  → dashboard + all scan modules
        admin    → everything (scan modules + model manager + system architecture)

    NOTE: This is UI convenience only — the real access gate is
          @role_required on each route. Never rely on sidebar
          absence as a security control.
    """
    all_items = [
        # ── Dashboard — all roles ──────────────────────────────────────────
        {
            "id":    "dashboard",
            "label": "Dashboard",
            "icon":  "grid",
            "endpoint": "dashboard_bp.index",
            "roles": ["visitor", "analyst", "admin"],
        },

        # ── Scan modules — analyst + admin ─────────────────────────────────
        {
            "id":    "email_scan",
            "label": "Email Scan",
            "icon":  "mail",
            "endpoint": "email_scan_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "url_intel",
            "label": "URL Intelligence",
            "icon":  "link",
            "endpoint": "url_intel_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "network_scan",
            "label": "Network Scan",
            "icon":  "wifi",
            "endpoint": "network_scan_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "detection_rules",
            "label": "Detection Rules",
            "icon":  "filter",
            "endpoint": "rules_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "ml_classifier",
            "label": "ML Classifier",
            "icon":  "cpu",
            "endpoint": "ml_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "attachment",
            "label": "Attachment Analysis",
            "icon":  "paperclip",
            "endpoint": "attachment_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "image_analysis",
            "label": "Image Analysis",
            "icon":  "image",
            "endpoint": "image_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "ai_detection",
            "label": "AI Detection",
            "icon":  "zap",
            "endpoint": "ai_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "platform_monitor",
            "label": "Platform Monitor",
            "icon":  "monitor",
            "endpoint": "platform_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "risk_score",
            "label": "Risk Engine",
            "icon":  "shield",
            "endpoint": "risk_score_bp.index",
            "roles": ["analyst", "admin"],
        },
        {
            "id":    "alerts",
            "label": "Alerts & Audit",
            "icon":  "bell",
            "endpoint": "alerts_bp.index",
            "roles": ["analyst", "admin"],
        },

        # ── Admin-only modules ─────────────────────────────────────────────
        {
            "id":    "model_mgmt",
            "label": "Model Manager",
            "icon":  "box",
            "endpoint": "model_mgmt_bp.index",
            "roles": ["admin"],
        },
        {
            "id":    "architecture",
            "label": "System Architecture",
            "icon":  "server",
            "endpoint": "architecture_bp.index",
            "roles": ["admin"],
        },
    ]

    return [item for item in all_items if role in item["roles"]]


# ── Application factory ────────────────────────────────────────────────────────

def create_app(config_name: str = "default") -> Flask:
    """
    Create and return a fully configured Flask application.

    Args:
        config_name: "development", "production", or "testing"
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
        static_folder=static_folder,
    )

    # ── Load configuration ─────────────────────────────────────────────────
    app.config.from_object(
        config_map.get(config_name, config_map["default"])
    )

    # SECRET_KEY guard — sessions silently break without this.
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "SECRET_KEY is not set in config. "
            "Sessions and @role_required will not work without it."
        )

    # ── Initialise SQLAlchemy ──────────────────────────────────────────────
    db.init_app(app)

    # ── Register blueprints ────────────────────────────────────────────────
    _register_blueprints(app)

    # ── Context processor ──────────────────────────────────────────────────
    # Single source of truth for sidebar, role, role_label, role_icon.
    # Injected into EVERY template automatically.
    # Routes MUST NOT pass any of these values manually.
    # get_sidebar_config() is ALWAYS called as get_sidebar_config(role) —
    # never as get_sidebar_config() with no args, never as a bare reference.

    @app.context_processor
    def inject_globals():
        role     = session.get("role", _DEFAULT_ROLE)
        role_cfg = _ROLES.get(role, _ROLES[_DEFAULT_ROLE])
        return {
            "sidebar":    get_sidebar_config(role),      # role always passed
            "role":       role,
            "role_label": role_cfg["label"],
            "role_icon":  role_cfg["icon"],
        }

    # ── Error handlers ─────────────────────────────────────────────────────

    @app.errorhandler(403)
    def forbidden(e):
        # role_label is already in template context via inject_globals.
        # Do NOT pass it manually here.
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        logger.exception("Unhandled server error: %s", e)
        return render_template("500.html"), 500

    # ── Create database tables ─────────────────────────────────────────────
    _setup_database(app)

    logger.info(
        "MAHORAGA Sentinel app created — RBAC active "
        "(visitor / analyst / admin)."
    )
    return app


# ── Blueprint registration ─────────────────────────────────────────────────────

def _register_blueprints(app: Flask) -> None:
    """
    Register all Flask blueprints.

    Architecture rule: app.register_blueprint() is ALWAYS called with NO
    url_prefix argument. Each blueprint defines its own url_prefix in its
    Blueprint() constructor. Breaking this rule causes double-prefixed routes.

    model_mgmt_bp and architecture_bp are REQUIRED, not optional.
    They carry @role_required("admin") on every route — a placeholder fallback
    would silently remove that enforcement. Import errors here must crash fast.
    """

    # ── Phase 0 — Dashboard ────────────────────────────────────────────────
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

    # ── Phases 7–11, 13–14 — Soft-optional scan modules ───────────────────
    # These are analyst-accessible scan modules. A missing file logs a warning
    # and skips registration — the sidebar item simply won't resolve.
    # They do NOT fall back to a placeholder page because that would shadow
    # any future real blueprint registered at the same URL.
    _optional_scan_blueprints = [
        ("backend.app.routes.image_analysis",  "image_bp",      "Phase 7  — Image Analysis"),
        ("backend.app.routes.ai_detection",    "ai_bp",         "Phase 8  — AI Detection"),
        ("backend.app.routes.platform_monitor","platform_bp",   "Phase 9  — Platform Monitor"),
        ("backend.app.routes.risk_score",      "risk_score_bp", "Phase 10 — Risk Engine"),
        ("backend.app.routes.alerts",          "alerts_bp",     "Phase 13 — Alerts & Audit"),
        ("backend.app.routes.extension",       "extension_bp",  "Phase 14 — Extension"),
    ]

    for module_path, bp_name, label in _optional_scan_blueprints:
        try:
            module = importlib.import_module(module_path)
            bp     = getattr(module, bp_name)
            app.register_blueprint(bp)          # NO url_prefix here
            logger.debug("Registered blueprint: %s", bp_name)
        except (ImportError, AttributeError) as exc:
            logger.warning(
                "Blueprint %s not registered (%s): %s",
                bp_name, label, exc,
            )

    # ── Phase 12 — Model Manager (REQUIRED — admin only) ──────────────────
    # NEVER made optional. @role_required("admin") is on every route.
    # An import failure here must raise and halt startup — a missing file
    # must not silently fall back to an unprotected placeholder.
    from backend.app.routes.model_mgmt import model_mgmt_bp
    app.register_blueprint(model_mgmt_bp)       # url_prefix="/models" set in blueprint

    # ── Phase 15 — System Architecture (REQUIRED — admin only) ────────────
    # Same rule as model_mgmt_bp — required, never optional.
    from backend.app.routes.architecture import architecture_bp
    app.register_blueprint(architecture_bp)     # url_prefix="/architecture" set in blueprint


# ── Database setup ─────────────────────────────────────────────────────────────

def _setup_database(app: Flask) -> None:
    with app.app_context():
        try:
            import backend.app.models  # noqa: F401 — registers all ORM models
            db.create_all()
            logger.info("Database tables created / verified.")
        except Exception as exc:
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "unknown")
            logger.error(
                "\n%s\n"
                "DATABASE ERROR: Cannot create tables.\n"
                "URI: %s\n"
                "Reason: %s\n"
                "Fix: ensure the 'database/' directory exists at project root.\n"
                "Run: mkdir database\n"
                "%s",
                "=" * 60, db_uri, exc, "=" * 60,
            )
            raise
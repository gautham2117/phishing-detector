# backend/api/main.py
# FastAPI application entry point.
# All HuggingFace models are loaded once at startup via the lifespan hook.

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.scan_router        import router as scan_router
from backend.modules.system_health  import record_request

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan — model loading at startup
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Code before yield  → runs at startup.
    Code after  yield  → runs at shutdown.
    Models are loaded here so they are ready before the first request.
    """
    logger.info("=== FastAPI starting — loading ML models ===")
    try:
        from backend.ml.model_loader import load_all_models
        load_all_models()
        logger.info("=== All models loaded — ready to serve ===")
    except Exception as e:
        # Server still starts even if model loading fails.
        # Individual endpoints fall back to rule-based results.
        logger.error(f"Model loading error (non-fatal): {e}")
    yield
    logger.info("=== FastAPI shutting down ===")


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Phishing Detection API",
    description=(
        "Real-time AI/ML phishing and threat detection endpoints.\n\n"
        "## Phases\n"
        "- **Phase 1** — Email Scanning\n"
        "- **Phase 2** — URL Intelligence\n"
        "- **Phase 3** — Network Scanning\n"
        "- **Phase 4** — Rule Engine\n"
        "- **Phase 5** — ML Classifier\n"
        "- **Phase 6** — File & Attachment Analysis\n"
        "- **Phase 7** — Image Analysis\n"
        "- **Phase 8** — AI Content Detection\n"
        "- **Phase 9** — Platform Monitor\n"
        "- **Phase 10** — Risk Score Aggregator\n"
        "- **Phase 11** — Live Monitor\n"
        "- **Phase 12** — Model Management\n"
        "- **Phase 13** — Alerts & Audit\n"
        "- **Phase 14** — Browser Extension\n"
        "- **Phase 15** — System Architecture\n"
        "- **Phase 16** — Threat Explanation\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ─────────────────────────────────────────────────────────────────────────────
# CORS — allow Flask frontend on port 5000 and Chrome extension
# ─────────────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5000",
        "http://localhost:5000",
        "http://127.0.0.1:8001",
        "null",                   # Chrome extension uses null origin
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 15 — Request rate counter middleware
# Records every incoming request timestamp for the request rate graph.
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def request_counter_middleware(request: Request, call_next):
    record_request()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error("Unhandled exception in request: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": "Internal server error."},
        )
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

app.include_router(scan_router, prefix="/api")


# ─────────────────────────────────────────────────────────────────────────────
# Root health check
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check():
    """
    Quick status check used by the dashboard module health panel.
    Returns the loaded/failed status of every ML model.
    """
    try:
        from backend.ml.model_loader import MODEL_REGISTRY
        models = {k: (v is not None) for k, v in MODEL_REGISTRY.items()}
    except Exception:
        models = {}

    return {
        "status":  "online",
        "service": "phishing-detection-api",
        "version": "1.0.0",
        "models":  models,
    }


@app.get("/", tags=["System"])
async def root():
    """Redirect hint — visit /docs for full Swagger UI."""
    return {
        "message": "PhishGuard API is running.",
        "docs":    "http://127.0.0.1:8001/docs",
        "health":  "http://127.0.0.1:8001/health",
    }
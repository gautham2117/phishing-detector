# backend/api/main.py
# FastAPI application entry point.
# All HuggingFace models are loaded once at startup via the lifespan hook.

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.scan_router import router as scan_router

logger = logging.getLogger(__name__)


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


app = FastAPI(
    title="Phishing Detection API",
    description="Real-time AI/ML phishing and threat detection endpoints.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Allow the Flask frontend (port 5000) to call this API (port 8001)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5000",
        "http://localhost:5000"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")


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
        "models":  models
    }
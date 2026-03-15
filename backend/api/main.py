# main.py  (updated — add lifespan startup event)

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .scan_router import router as scan_router
from backend.ml.model_loader import load_all_models
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Code BEFORE 'yield' runs at startup.
    Code AFTER 'yield' runs at shutdown.

    We load all HuggingFace models here so they are ready
    before the first request arrives. This is the ONLY place
    models should be loaded — never inside a request handler.
    """
    logger.info("=== FastAPI starting up — loading ML models ===")
    load_all_models()
    logger.info("=== All models loaded — ready to serve requests ===")
    yield
    logger.info("=== FastAPI shutting down ===")


app = FastAPI(
    title="Phishing Detection API",
    description="Real-time AI/ML phishing and threat detection endpoints.",
    version="1.0.0",
    lifespan=lifespan   # ← hook in the startup model loading
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")


@app.get("/health")
async def health_check():
    from backend.ml.model_loader import MODEL_REGISTRY
    loaded = {k: (v is not None) for k, v in MODEL_REGISTRY.items()}
    return {"status": "online", "models": loaded}
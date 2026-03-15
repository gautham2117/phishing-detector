# main.py
# FastAPI application. This is the detection microservice layer.
# All ML models are loaded ONCE here at startup and cached globally.

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .scan_router import router as scan_router

# Create the FastAPI app with metadata for Swagger UI
app = FastAPI(
    title="Phishing Detection API",
    description="Real-time AI/ML phishing and threat detection endpoints.",
    version="1.0.0",
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc"      # Alternative ReDoc UI
)

# Allow the Flask frontend (port 5000) to call this API (port 8001)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include the scan routes (we'll fill these in per module)
app.include_router(scan_router, prefix="/api")


@app.get("/health")
async def health_check():
    """Quick status check — used by the dashboard module health panel."""
    return {"status": "online", "service": "phishing-detection-api"}
# run_fastapi.py
# Entry point to start the FastAPI detection API.
# Run: python backend/run_fastapi.py
# Swagger docs will be at: http://127.0.0.1:8001/docs

import uvicorn
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

if __name__ == "__main__":
    print("Starting FastAPI on http://127.0.0.1:8001")
    print("Swagger UI available at: http://127.0.0.1:8001/docs")
    uvicorn.run(
        "api.main:app",     # module:object
        host="127.0.0.1",
        port=8001,
        reload=True         # auto-reload on file changes (dev only)
    )
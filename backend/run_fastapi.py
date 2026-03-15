# backend/run_fastapi.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn

if __name__ == "__main__":
    print("Starting FastAPI on http://127.0.0.1:8001")
    print("Swagger UI: http://127.0.0.1:8001/docs")
    uvicorn.run(
        "backend.api.main:app",
        host="127.0.0.1",
        port=8001,
        reload=True
    )
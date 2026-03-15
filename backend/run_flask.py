# backend/run_flask.py
import os
import sys

# Insert the project root (parent of backend/) so that
# "from backend.app..." imports resolve correctly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app

env = os.environ.get("FLASK_ENV", "development")
app = create_app(config_name=env)

if __name__ == "__main__":
    print("Starting Flask Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
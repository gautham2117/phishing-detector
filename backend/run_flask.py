# run_flask.py
# Entry point to start the Flask web dashboard.
# Run: python backend/run_flask.py

import os
import sys

# Add backend directory to Python path so imports resolve correctly
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app

# Create the app with the development config by default.
# Set FLASK_ENV=production in .env for production config.
env = os.environ.get("FLASK_ENV", "development")
app = create_app(config_name=env)

if __name__ == "__main__":
    print("Starting Flask Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
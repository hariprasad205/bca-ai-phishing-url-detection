"""Application Entry Point.

Starts development server or exposes application instance for WSGI deployment.
"""
import os
from app import create_app

env_mode = os.getenv("FLASK_ENV", "development")
app = create_app(env_mode)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)

"""Flask Application Factory module.

Initializes extensions, registers blueprints, sets security headers,
and handles custom application error pages.
"""
import os
from flask import Flask, render_template
from config import config_by_name
from app.extensions import db, migrate, login_manager, csrf
from app.cli import register_cli_commands


def create_app(config_name: str = "default") -> Flask:
    """Application factory for Phishing URL Detection System."""
    app = Flask(__name__)
    
    # Load configuration
    cfg = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(cfg)

    # Ensure required folders exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["MODELS_FOLDER"], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    # Register CLI commands
    register_cli_commands(app)

    # Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html", error=error), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html", error=error), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template("errors/500.html", error=error), 500

    # Inject context variables
    @app.context_processor
    def inject_global_template_vars():
        return {
            "app_name": "PhishShield AI",
            "app_full_title": "AI-Based Phishing URL Detection System Using Machine Learning",
        }

    # Security response headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    return app

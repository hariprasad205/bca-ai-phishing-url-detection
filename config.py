import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base configuration loaded from environment variables."""
    SECRET_KEY = os.getenv("SECRET_KEY", "phishing-defense-production-grade-key-2026")
    
    # MySQL Database Configuration using PyMySQL
    # Default mandatory database is MySQL 8.x via PyMySQL
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "rootpassword")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "3306")
    DB_NAME = os.getenv("DB_NAME", "phishing_detection_db")
    
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # Uploads & Storage Folders
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB max
    UPLOAD_FOLDER = os.path.join(BASE_DIR, os.getenv("UPLOAD_FOLDER", "data/uploads"))
    MODELS_FOLDER = os.path.join(BASE_DIR, os.getenv("MODELS_FOLDER", "models_storage"))
    
    # ML Scoring and Selection Parameters
    MIN_MODEL_RECALL = float(os.getenv("MIN_MODEL_RECALL", 0.80))
    MAX_LATENCY_MS = float(os.getenv("MAX_LATENCY_MS", 100.0))
    SCORE_WEIGHT_RECALL = float(os.getenv("SCORE_WEIGHT_RECALL", 0.40))
    SCORE_WEIGHT_F1 = float(os.getenv("SCORE_WEIGHT_F1", 0.30))
    SCORE_WEIGHT_PRECISION = float(os.getenv("SCORE_WEIGHT_PRECISION", 0.20))
    SCORE_WEIGHT_SPEED = float(os.getenv("SCORE_WEIGHT_SPEED", 0.10))

    # Security & Sessions
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Rate limiting thresholds
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per hour")
    RATELIMIT_AUTH = os.getenv("RATELIMIT_AUTH", "15 per minute")
    RATELIMIT_SCAN = os.getenv("RATELIMIT_SCAN", "60 per minute")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    # If DATABASE_URL is explicitly set to SQLite or MySQL, it will be respected


class TestingConfig(Config):
    """Testing configuration with in-memory SQLite and disabled CSRF for automated tests."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "data/test_uploads")
    MODELS_FOLDER = os.path.join(BASE_DIR, "models_storage/test_models")


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}

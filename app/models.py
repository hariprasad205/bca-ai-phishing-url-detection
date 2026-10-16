"""SQLAlchemy Database Models for Phishing Detection System.

Defines schemas and relationships for:
- users
- scans
- scan_features
- datasets
- models
- training_runs
- audit_logs
"""
import json
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """User account entity supporting role-based access control (user vs admin)."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False, index=True)  # 'user' or 'admin'
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    scans = db.relationship("Scan", backref="user", cascade="all, delete-orphan", lazy="dynamic")
    audit_logs = db.relationship("AuditLog", backref="user", foreign_keys="AuditLog.user_id", lazy="dynamic")

    def set_password(self, password: str) -> None:
        """Hash and store user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify candidate password against stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        """Check if user has administrator privileges."""
        return self.role == "admin"

    @property
    def is_active(self) -> bool:
        """Flask-Login required active property."""
        return self.is_active_account

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader callback."""
    return db.session.get(User, int(user_id))


class Scan(db.Model):
    """Individual URL scan record with prediction output and risk score."""
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True
    )
    url = db.Column(db.Text, nullable=False)
    url_hash = db.Column(db.String(64), nullable=False, index=True)
    prediction_label = db.Column(db.String(20), nullable=False, index=True)  # 'phishing' or 'legitimate'
    risk_score = db.Column(db.Float, nullable=False, index=True)  # 0.0 to 100.0
    risk_category = db.Column(db.String(20), nullable=False, index=True)  # 'Low', 'Moderate', 'High', 'Critical'
    probability = db.Column(db.Float, nullable=False)  # 0.0 to 1.0 (calibrated phishing probability)
    model_version = db.Column(db.String(64), nullable=False)
    model_id = db.Column(
        db.Integer,
        db.ForeignKey("models.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True
    )
    latency_ms = db.Column(db.Float, nullable=False)  # Milliseconds
    explanation_json = db.Column(db.Text, nullable=True)  # JSON-encoded suspicious tokens, features
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationships
    features = db.relationship("ScanFeature", backref="scan", uselist=False, cascade="all, delete-orphan")
    model = db.relationship("MLModel", backref="scans")

    @property
    def explanation(self) -> dict:
        """Parse explanation JSON safely."""
        if not self.explanation_json:
            return {}
        try:
            return json.loads(self.explanation_json)
        except Exception:
            return {}

    @explanation.setter
    def explanation(self, data: dict) -> None:
        """Serialize explanation dictionary to JSON."""
        self.explanation_json = json.dumps(data) if data is not None else None

    def __repr__(self) -> str:
        return f"<Scan id={self.id} label='{self.prediction_label}' risk={self.risk_score}>"


class ScanFeature(db.Model):
    """Lexical features extracted from a scanned URL (1-to-1 with Scan)."""
    __tablename__ = "scan_features"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id", ondelete="CASCADE", onupdate="CASCADE"),
        unique=True,
        nullable=False,
        index=True
    )
    url_length = db.Column(db.Integer, nullable=False)
    hostname_length = db.Column(db.Integer, nullable=False)
    num_dots = db.Column(db.Integer, nullable=False)
    num_hyphens = db.Column(db.Integer, nullable=False)
    num_digits = db.Column(db.Integer, nullable=False)
    num_subdomains = db.Column(db.Integer, nullable=False)
    is_https = db.Column(db.Integer, nullable=False)  # 1 or 0
    is_ip = db.Column(db.Integer, nullable=False)     # 1 or 0
    suspicious_token_count = db.Column(db.Integer, nullable=False)
    path_length = db.Column(db.Integer, nullable=False)
    query_length = db.Column(db.Integer, nullable=False)
    has_at_symbol = db.Column(db.Integer, nullable=False)  # 1 or 0
    percent_encoded_count = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    def to_dict(self) -> dict:
        """Convert features to standardized dictionary matching ML model schema."""
        return {
            "url_length": self.url_length,
            "hostname_length": self.hostname_length,
            "num_dots": self.num_dots,
            "num_hyphens": self.num_hyphens,
            "num_digits": self.num_digits,
            "num_subdomains": self.num_subdomains,
            "is_https": self.is_https,
            "is_ip": self.is_ip,
            "suspicious_token_count": self.suspicious_token_count,
            "path_length": self.path_length,
            "query_length": self.query_length,
            "has_at_symbol": self.has_at_symbol,
            "percent_encoded_count": self.percent_encoded_count,
        }


class Dataset(db.Model):
    """Uploaded and validated URL dataset entity."""
    __tablename__ = "datasets"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)
    file_size_bytes = db.Column(db.Integer, nullable=False)
    upload_status = db.Column(db.String(32), default="pending", nullable=False, index=True)  # 'valid', 'invalid'
    total_rows = db.Column(db.Integer, default=0, nullable=False)
    phishing_count = db.Column(db.Integer, default=0, nullable=False)
    legitimate_count = db.Column(db.Integer, default=0, nullable=False)
    duplicate_rows = db.Column(db.Integer, default=0, nullable=False)
    missing_values_count = db.Column(db.Integer, default=0, nullable=False)
    validation_errors_json = db.Column(db.Text, nullable=True)
    uploaded_by_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True
    )
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    # Relationships
    training_runs = db.relationship("TrainingRun", backref="dataset", cascade="all, delete-orphan", lazy="dynamic")
    uploader = db.relationship("User", foreign_keys=[uploaded_by_id], backref="uploaded_datasets")

    @property
    def validation_errors(self) -> list:
        if not self.validation_errors_json:
            return []
        try:
            return json.loads(self.validation_errors_json)
        except Exception:
            return [self.validation_errors_json]

    @validation_errors.setter
    def validation_errors(self, errs: list) -> None:
        self.validation_errors_json = json.dumps(errs) if errs is not None else None


class MLModel(db.Model):
    """Trained machine-learning model artifact with evaluation metrics."""
    __tablename__ = "models"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), nullable=False)  # 'Random Forest Classifier', etc.
    algorithm = db.Column(db.String(64), nullable=False, index=True)  # 'random_forest', 'logistic_regression'
    version = db.Column(db.String(64), unique=True, nullable=False, index=True)
    artifact_path = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False, index=True)
    feature_names_json = db.Column(db.Text, nullable=False)  # JSON array of ordered feature names
    hyperparameters_json = db.Column(db.Text, nullable=True)  # JSON string of training hyperparameters
    
    # Evaluation Metrics
    accuracy = db.Column(db.Float, nullable=False)
    precision_score = db.Column(db.Float, nullable=False)
    recall_score = db.Column(db.Float, nullable=False)
    f1_score = db.Column(db.Float, nullable=False)
    roc_auc = db.Column(db.Float, nullable=True)
    confusion_matrix_json = db.Column(db.Text, nullable=True)  # JSON 2x2 matrix [[TN, FP], [FN, TP]]
    avg_latency_ms = db.Column(db.Float, nullable=False)
    training_time_sec = db.Column(db.Float, nullable=False)
    selection_score = db.Column(db.Float, nullable=False, default=0.0)
    selection_notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    training_runs = db.relationship("TrainingRun", backref="model", lazy="dynamic")

    @property
    def feature_names(self) -> list:
        try:
            return json.loads(self.feature_names_json)
        except Exception:
            return []

    @property
    def hyperparameters(self) -> dict:
        if not self.hyperparameters_json:
            return {}
        try:
            return json.loads(self.hyperparameters_json)
        except Exception:
            return {}

    @property
    def confusion_matrix(self) -> list:
        if not self.confusion_matrix_json:
            return [[0, 0], [0, 0]]
        try:
            return json.loads(self.confusion_matrix_json)
        except Exception:
            return [[0, 0], [0, 0]]


class TrainingRun(db.Model):
    """Audit entity tracking an execution of the model training and selection pipeline."""
    __tablename__ = "training_runs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dataset_id = db.Column(
        db.Integer,
        db.ForeignKey("datasets.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
        index=True
    )
    model_id = db.Column(
        db.Integer,
        db.ForeignKey("models.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True
    )
    run_identifier = db.Column(db.String(64), unique=True, nullable=False, index=True)
    status = db.Column(db.String(32), default="started", nullable=False, index=True)  # 'completed', 'failed'
    evaluated_models_count = db.Column(db.Integer, default=0, nullable=False)
    selected_model_name = db.Column(db.String(64), nullable=True)
    evaluation_summary_json = db.Column(db.Text, nullable=True)  # JSON breakdown of all candidate models
    selection_reason = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    initiated_by_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True
    )
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    initiator = db.relationship("User", foreign_keys=[initiated_by_id], backref="training_runs")

    @property
    def evaluation_summary(self) -> list:
        if not self.evaluation_summary_json:
            return []
        try:
            return json.loads(self.evaluation_summary_json)
        except Exception:
            return []


class AuditLog(db.Model):
    """Security and system event audit log."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL", onupdate="CASCADE"),
        nullable=True,
        index=True
    )
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action='{self.action}' user_id={self.user_id}>"

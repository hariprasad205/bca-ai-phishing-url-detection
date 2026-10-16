"""Administrator routes for Dataset Management, Model Training, Comparison, and Auditing."""
import os
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    abort, Response, current_app
)
from flask_login import login_required, current_user

from app.extensions import db
from app.models import User, Scan, Dataset, MLModel, TrainingRun, AuditLog
from app.auth.decorators import admin_required
from app.admin.forms import DatasetUploadForm, TrainModelsForm
from app.ml.dataset_service import save_and_register_dataset
from app.ml.training_service import run_training_pipeline, activate_specific_model
from app.reporting.csv_generator import (
    generate_scans_csv, generate_models_csv, generate_training_history_csv
)
from app.reporting.timezone import get_device_timezone

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.before_request
@login_required
@admin_required
def admin_protect():
    """Double-check administrative authorization on all blueprint endpoints."""
    pass


@admin_bp.route("")
@admin_bp.route("/")
def admin_dashboard():
    """System-wide administration overview with performance metrics and activity summary."""
    total_users = User.query.count()
    total_scans = Scan.query.count()
    total_phishing = Scan.query.filter_by(prediction_label="phishing").count()
    total_legitimate = Scan.query.filter_by(prediction_label="legitimate").count()

    active_model = MLModel.query.filter_by(is_active=True).first()
    all_models = MLModel.query.order_by(MLModel.created_at.desc()).all()
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(8).all()
    recent_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
    datasets_count = Dataset.query.count()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_scans=total_scans,
        total_phishing=total_phishing,
        total_legitimate=total_legitimate,
        active_model=active_model,
        all_models=all_models,
        recent_scans=recent_scans,
        recent_logs=recent_logs,
        datasets_count=datasets_count,
    )


@admin_bp.route("/users")
def users_list():
    """User account management."""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/users/<int:user_id>/toggle-status", methods=["POST"])
def toggle_user_status(user_id):
    """Activate or deactivate user account."""
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot deactivate your own administrative account.", "warning")
        return redirect(url_for("admin.users_list"))

    user.is_active_account = not user.is_active_account
    db.session.commit()

    log = AuditLog(
        user_id=current_user.id,
        action="ADMIN_TOGGLE_USER_STATUS",
        details=f"Admin changed active status of user '{user.username}' (ID: {user.id}) to {user.is_active_account}.",
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()

    flash(f"Account '{user.username}' status set to {'Active' if user.is_active_account else 'Deactivated'}.", "success")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/datasets")
def datasets_list():
    """List all uploaded datasets with row counts and balance."""
    datasets = Dataset.query.order_by(Dataset.created_at.desc()).all()
    return render_template("admin/datasets.html", datasets=datasets)


@admin_bp.route("/datasets/upload", methods=["GET", "POST"])
def dataset_upload():
    """Upload and validate a new CSV dataset."""
    form = DatasetUploadForm()
    if form.validate_on_submit():
        file_storage = form.csv_file.data
        try:
            dataset_record, validation = save_and_register_dataset(file_storage, user_id=current_user.id)
            if validation["valid"]:
                flash(
                    f"Dataset '{dataset_record.original_filename}' uploaded and validated successfully! "
                    f"({dataset_record.total_rows} rows: {dataset_record.phishing_count} phishing, {dataset_record.legitimate_count} legitimate).",
                    "success"
                )
                return redirect(url_for("admin.dataset_detail", dataset_id=dataset_record.id))
            else:
                err_msg = "; ".join(validation.get("errors", ["Validation failed."]))
                flash(f"Dataset upload rejected: {err_msg}", "danger")
                return redirect(url_for("admin.dataset_detail", dataset_id=dataset_record.id))
        except Exception as e:
            flash(f"Upload error: {str(e)}", "danger")

    return render_template("admin/dataset_upload.html", form=form)


@admin_bp.route("/datasets/<int:dataset_id>")
def dataset_detail(dataset_id):
    """View dataset validation report, balance, and preview rows."""
    dataset = db.session.get(Dataset, dataset_id)
    if not dataset:
        abort(404)
    return render_template("admin/dataset_detail.html", dataset=dataset)


@admin_bp.route("/training", methods=["GET", "POST"])
def training():
    """Initiate machine-learning training pipeline on a selected dataset."""
    form = TrainModelsForm()
    valid_datasets = Dataset.query.filter_by(upload_status="valid").all()
    form.dataset_id.choices = [(d.id, f"{d.original_filename} ({d.total_rows} rows)") for d in valid_datasets]

    if form.validate_on_submit():
        selected_dataset_id = form.dataset_id.data
        try:
            run_record, active_model = run_training_pipeline(selected_dataset_id, initiated_by_id=current_user.id)
            if active_model:
                flash(
                    f"Training pipeline completed successfully! Active Model set to: {active_model.name} "
                    f"(Accuracy: {active_model.accuracy:.4f}, Recall: {active_model.recall_score:.4f}, F1: {active_model.f1_score:.4f}).",
                    "success"
                )
            else:
                flash(f"Training finished but no model satisfied the minimum validation thresholds: {run_record.selection_reason}", "warning")
            return redirect(url_for("admin.model_comparison"))
        except Exception as e:
            flash(f"Training failed: {str(e)}", "danger")

    return render_template("admin/training.html", form=form, valid_datasets=valid_datasets)


@admin_bp.route("/models")
def models_list():
    """List all trained model artifacts."""
    models = MLModel.query.order_by(MLModel.created_at.desc()).all()
    active_model = MLModel.query.filter_by(is_active=True).first()
    return render_template("admin/models.html", models=models, active_model=active_model)


@admin_bp.route("/models/<int:model_id>/activate", methods=["POST"])
def activate_model(model_id):
    """Manually activate a specific trained model."""
    try:
        model = activate_specific_model(model_id, user_id=current_user.id)
        flash(f"Model '{model.name}' ({model.version}) is now the active production model.", "success")
    except Exception as e:
        flash(f"Activation failed: {str(e)}", "danger")
    return redirect(url_for("admin.model_comparison"))


@admin_bp.route("/model-comparison")
def model_comparison():
    """Comprehensive comparison table and visualization of all candidate algorithms."""
    models = MLModel.query.order_by(MLModel.created_at.desc()).all()
    active_model = MLModel.query.filter_by(is_active=True).first()

    return render_template(
        "admin/model_comparison.html",
        models=models,
        active_model=active_model,
    )


@admin_bp.route("/training-history")
def training_history():
    """Historical training runs audit log and model selection reasons."""
    runs = TrainingRun.query.order_by(TrainingRun.created_at.desc()).all()
    return render_template("admin/training_history.html", runs=runs)


@admin_bp.route("/audit-logs")
def audit_logs():
    """System-wide security and administration audit logs."""
    page = request.args.get("page", 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template("admin/audit_logs.html", pagination=pagination, logs=pagination.items)


# ==================== CSV EXPORT ROUTES (ADMIN ONLY) ====================

@admin_bp.route("/export/scans.csv")
def export_all_scans_csv():
    """Download all system scan records across all users (Admin only)."""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    try:
        local_timezone = get_device_timezone(request.args.get("timezone"))
    except ValueError:
        abort(400, description="Unknown timezone")
    csv_buffer = generate_scans_csv(
        scans, include_user=True, local_timezone=local_timezone
    )
    filename = f"system_scans_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@admin_bp.route("/export/models.csv")
def export_models_csv():
    """Download evaluation metrics comparison table as CSV."""
    models = MLModel.query.order_by(MLModel.created_at.desc()).all()
    csv_buffer = generate_models_csv(models)
    filename = f"model_comparison_metrics_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@admin_bp.route("/export/training-history.csv")
def export_training_history_csv():
    """Download training history runs as CSV."""
    runs = TrainingRun.query.order_by(TrainingRun.created_at.desc()).all()
    csv_buffer = generate_training_history_csv(runs)
    filename = f"training_runs_audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

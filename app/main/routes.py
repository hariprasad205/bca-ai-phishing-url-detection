"""User-facing routes (Dashboard, Scanner, History, Detail, PDF Audit, CSV Export)."""
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    abort, Response, send_file
)
from flask_login import login_required, current_user
from sqlalchemy import func

from app.extensions import db
from app.models import Scan, MLModel
from app.main.forms import UrlScanForm
from app.ml.prediction_service import predict_url
from app.reporting.pdf_generator import generate_scan_audit_pdf
from app.reporting.csv_generator import generate_scans_csv
from app.reporting.timezone import get_device_timezone

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Application landing page / overview."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("user/index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """User personal dashboard with stats, risk breakdown, and quick scanner."""
    user_scans_q = Scan.query.filter_by(user_id=current_user.id)

    total_scans = user_scans_q.count()
    phishing_count = user_scans_q.filter_by(prediction_label="phishing").count()
    legitimate_count = user_scans_q.filter_by(prediction_label="legitimate").count()

    # Risk categories breakdown
    low_risk = user_scans_q.filter_by(risk_category="Low").count()
    moderate_risk = user_scans_q.filter_by(risk_category="Moderate").count()
    high_risk = user_scans_q.filter_by(risk_category="High").count()
    critical_risk = user_scans_q.filter_by(risk_category="Critical").count()

    recent_scans = user_scans_q.order_by(Scan.created_at.desc()).limit(7).all()
    active_model = MLModel.query.filter_by(is_active=True).first()

    scanner_form = UrlScanForm()

    return render_template(
        "user/dashboard.html",
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        risk_distribution={
            "Low": low_risk,
            "Moderate": moderate_risk,
            "High": high_risk,
            "Critical": critical_risk,
        },
        recent_scans=recent_scans,
        active_model=active_model,
        form=scanner_form,
    )


@main_bp.route("/scanner", methods=["GET"])
@login_required
def scanner():
    """Dedicated URL scanner interface."""
    form = UrlScanForm()
    return render_template("user/scanner.html", form=form)


@main_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    """Process URL scanning submission with real-time ML prediction."""
    form = UrlScanForm()
    if request.method == "POST" and form.validate_on_submit():
        raw_url = form.url.data.strip()
        try:
            scan_record, explanation = predict_url(raw_url, current_user.id)
            flash("URL successfully analyzed using active machine-learning model.", "success")
            return redirect(url_for("main.scan_detail", scan_id=scan_record.id))
        except Exception as e:
            flash(f"Scanning failed: {str(e)}", "danger")
            return render_template("user/scanner.html", form=form)

    return render_template("user/scanner.html", form=form)


@main_bp.route("/history")
@login_required
def history():
    """User scan history with search, category/label filtering, date range, and pagination."""
    page = request.args.get("page", 1, type=int)
    search_query = request.args.get("q", "").strip()
    label_filter = request.args.get("label", "").strip()
    category_filter = request.args.get("category", "").strip()
    start_date_str = request.args.get("start_date", "").strip()
    end_date_str = request.args.get("end_date", "").strip()

    query = Scan.query.filter_by(user_id=current_user.id)

    if search_query:
        query = query.filter(Scan.url.ilike(f"%{search_query}%"))
    if label_filter in ("phishing", "legitimate"):
        query = query.filter(Scan.prediction_label == label_filter)
    if category_filter in ("Low", "Moderate", "High", "Critical"):
        query = query.filter(Scan.risk_category == category_filter)

    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
            query = query.filter(Scan.created_at >= start_date)
        except ValueError:
            pass

    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            query = query.filter(Scan.created_at <= end_date)
        except ValueError:
            pass

    pagination = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=10, error_out=False)

    return render_template(
        "user/history.html",
        pagination=pagination,
        scans=pagination.items,
        search_query=search_query,
        label_filter=label_filter,
        category_filter=category_filter,
        start_date=start_date_str,
        end_date=end_date_str,
    )


@main_bp.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    """View detailed inspection results and feature breakdown for an individual scan."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    # Insecure Direct Object Reference (IDOR) Protection:
    # Users can view ONLY their own scans unless they hold administrator privileges.
    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    return render_template("user/scan_detail.html", scan=scan)


@main_bp.route("/scan/<int:scan_id>/audit.pdf")
@login_required
def scan_audit_pdf(scan_id):
    """Download ReportLab-generated PDF Audit Certificate."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    # Enforce IDOR authorization check on PDF download
    if scan.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    try:
        local_timezone = get_device_timezone(request.args.get("timezone"))
    except ValueError:
        abort(400, description="Unknown timezone")
    pdf_buffer = generate_scan_audit_pdf(scan, local_timezone)
    filename = f"URL_Audit_Report_{scan.id}_{scan.created_at.strftime('%Y%m%d')}.pdf"

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


@main_bp.route("/reports/export.csv")
@login_required
def export_user_scans_csv():
    """Download personal scan records as a sanitized CSV file."""
    # Strictly query requesting user's scan records only
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    try:
        local_timezone = get_device_timezone(request.args.get("timezone"))
    except ValueError:
        abort(400, description="Unknown timezone")
    csv_buffer = generate_scans_csv(
        user_scans, include_user=False, local_timezone=local_timezone
    )

    filename = f"my_scans_{current_user.username}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

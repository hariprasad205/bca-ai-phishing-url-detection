"""CSV Report Generation Service.

Provides secure CSV exports with injection sanitization against spreadsheet formula exploits
(=, +, -, @), UTF-8 encoding, and permission-isolated queries.
"""
import csv
import io
from datetime import timezone, tzinfo
from app.models import Scan, MLModel, TrainingRun
from app.reporting.timezone import format_local_timestamp


def sanitize_csv_cell(value) -> str:
    """Neutralize formula injection by prefixing formula trigger characters with a single quote."""
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


def generate_scans_csv(
    scans: list[Scan],
    include_user: bool = False,
    local_timezone: tzinfo | None = None,
) -> io.StringIO:
    """Generate CSV string buffer from a list of Scan records."""
    if local_timezone is None:
        local_timezone = timezone.utc
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Scan ID",
        "Timestamp (Local Time)",
        "Target URL",
        "Prediction",
        "Risk Score (0-100)",
        "Risk Category",
        "Probability",
        "Model Version",
        "Latency (ms)",
    ]
    if include_user:
        headers.insert(1, "User ID")
        headers.insert(2, "Username")

    writer.writerow([sanitize_csv_cell(h) for h in headers])

    for s in scans:
        row = [
            s.id,
            format_local_timestamp(s.created_at, local_timezone),
            s.url,
            s.prediction_label,
            s.risk_score,
            s.risk_category,
            s.probability,
            s.model_version,
            s.latency_ms,
        ]
        if include_user:
            row.insert(1, s.user_id)
            row.insert(2, s.user.username if s.user else "Unknown")

        writer.writerow([sanitize_csv_cell(c) for c in row])

    output.seek(0)
    return output


def generate_models_csv(models: list[MLModel]) -> io.StringIO:
    """Generate CSV export for model comparison and benchmarking."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Model ID",
        "Algorithm Name",
        "Version",
        "Status",
        "Accuracy",
        "Precision",
        "Recall",
        "F1-Score",
        "ROC-AUC",
        "Avg Latency (ms)",
        "Training Time (s)",
        "Selection Score",
        "Created At",
    ]
    writer.writerow([sanitize_csv_cell(h) for h in headers])

    for m in models:
        row = [
            m.id,
            m.name,
            m.version,
            "ACTIVE" if m.is_active else "Inactive",
            f"{m.accuracy:.4f}",
            f"{m.precision_score:.4f}",
            f"{m.recall_score:.4f}",
            f"{m.f1_score:.4f}",
            f"{m.roc_auc:.4f}" if m.roc_auc is not None else "N/A",
            f"{m.avg_latency_ms:.2f}",
            f"{m.training_time_sec:.4f}",
            f"{m.selection_score:.4f}",
            m.created_at.strftime("%Y-%m-%d %H:%M:%S") if m.created_at else "",
        ]
        writer.writerow([sanitize_csv_cell(c) for c in row])

    output.seek(0)
    return output


def generate_training_history_csv(runs: list[TrainingRun]) -> io.StringIO:
    """Generate CSV export for training runs audit trail."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Run ID",
        "Dataset ID",
        "Dataset Filename",
        "Status",
        "Evaluated Models Count",
        "Selected Model",
        "Selection Reason",
        "Initiated By User ID",
        "Started At",
        "Completed At",
    ]
    writer.writerow([sanitize_csv_cell(h) for h in headers])

    for r in runs:
        row = [
            r.run_identifier,
            r.dataset_id,
            r.dataset.original_filename if r.dataset else "N/A",
            r.status,
            r.evaluated_models_count,
            r.selected_model_name or "None",
            r.selection_reason or "",
            r.initiated_by_id or "CLI/System",
            r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
            r.completed_at.strftime("%Y-%m-%d %H:%M:%S") if r.completed_at else "",
        ]
        writer.writerow([sanitize_csv_cell(c) for c in row])

    output.seek(0)
    return output

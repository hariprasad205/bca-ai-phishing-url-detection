"""Machine Learning Training Pipeline.

Trains Logistic Regression, Random Forest, and Decision Tree algorithms on held-out test splits,
computes true evaluation metrics without data leakage, serializes model artifacts,
and executes automatic model selection.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from flask import current_app
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

from app.extensions import db
from app.models import Dataset, MLModel, TrainingRun, AuditLog
from app.ml.feature_extraction import extract_features_vector, FEATURE_NAMES
from app.ml.dataset_service import LABEL_MAPPING
from app.ml.model_selector import select_best_model, calculate_selection_score


def load_dataset_features(dataset: Dataset) -> tuple[np.ndarray, np.ndarray, list]:
    """Extract or load tabular feature matrix X and label vector y."""
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    file_path = os.path.join(upload_folder, dataset.storage_filename)

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    try:
        df = pd.read_csv(file_path, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, encoding="latin-1")

    # Detect label column
    normalized_cols = {col.strip().lower(): col for col in df.columns}
    label_col = None
    for cand in ["label", "status", "target", "class", "result", "type"]:
        if cand in normalized_cols:
            label_col = normalized_cols[cand]
            break

    if not label_col:
        raise ValueError("Could not find a valid label column in dataset.")

    # Clean rows with missing labels
    df = df.dropna(subset=[label_col]).copy()
    raw_labels = df[label_col].astype(str).str.strip().str.lower()
    y = raw_labels.map(lambda x: LABEL_MAPPING.get(x, None)).to_numpy(dtype=int)

    # Check if precomputed or raw URL
    is_precomputed = all(col in df.columns for col in FEATURE_NAMES)

    if is_precomputed:
        X = df[FEATURE_NAMES].fillna(0).to_numpy(dtype=float)
    else:
        # Find URL column
        url_col = None
        for cand in ["url", "urls", "web_url", "link"]:
            if cand in normalized_cols:
                url_col = normalized_cols[cand]
                break
        if not url_col:
            raise ValueError("Dataset does not contain a 'url' column or complete precomputed features.")

        # Extract lexical features
        features_list = []
        for u in df[url_col]:
            features_list.append(extract_features_vector(str(u)))
        X = np.array(features_list, dtype=float)

    return X, y, FEATURE_NAMES


def run_training_pipeline(dataset_id: int, initiated_by_id: int = None) -> tuple[TrainingRun, MLModel | None]:
    """Execute complete end-to-end training, evaluation, comparison, and selection."""
    dataset = db.session.get(Dataset, dataset_id)
    if not dataset:
        raise ValueError(f"Dataset with ID {dataset_id} does not exist.")

    run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    models_folder = current_app.config["MODELS_FOLDER"]
    os.makedirs(models_folder, exist_ok=True)

    training_run = TrainingRun(
        dataset_id=dataset.id,
        run_identifier=run_id,
        status="running",
        initiated_by_id=initiated_by_id,
    )
    db.session.add(training_run)
    db.session.commit()

    try:
        X, y, feature_names = load_dataset_features(dataset)

        # Ensure balanced classes for split
        if len(np.unique(y)) < 2:
            raise ValueError("Dataset must contain both phishing and legitimate URL samples.")

        # Stratified split to prevent target distribution skew
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )

        # Fit Scaler strictly on training partition to eliminate data leakage
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Candidate Algorithms Definitions
        candidates_def = [
            {
                "name": "Random Forest Classifier",
                "algorithm": "random_forest",
                "model": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42),
                "params": {"n_estimators": 100, "max_depth": 12, "random_state": 42},
            },
            {
                "name": "Logistic Regression",
                "algorithm": "logistic_regression",
                "model": LogisticRegression(max_iter=1000, C=1.0, random_state=42),
                "params": {"max_iter": 1000, "C": 1.0, "random_state": 42},
            },
            {
                "name": "Decision Tree Classifier",
                "algorithm": "decision_tree",
                "model": DecisionTreeClassifier(max_depth=8, random_state=42),
                "params": {"max_depth": 8, "random_state": 42},
            },
        ]

        evaluated_results = []
        created_models = []

        for cand in candidates_def:
            alg_name = cand["name"]
            model_inst = cand["model"]
            
            # Train and measure wall-clock training duration
            t0 = time.perf_counter()
            model_inst.fit(X_train_scaled, y_train)
            train_time = round(time.perf_counter() - t0, 4)

            # Evaluate latency by timing multiple inference passes
            t_inf_start = time.perf_counter()
            y_pred = model_inst.predict(X_test_scaled)
            t_inf_end = time.perf_counter()
            avg_latency = round(((t_inf_end - t_inf_start) / len(X_test)) * 1000.0, 3)

            # Probabilities for ROC-AUC
            if hasattr(model_inst, "predict_proba"):
                y_prob = model_inst.predict_proba(X_test_scaled)[:, 1]
                try:
                    roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
                except Exception:
                    roc_auc = None
            else:
                roc_auc = None

            acc = round(float(accuracy_score(y_test, y_pred)), 4)
            prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
            rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
            f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
            cm = confusion_matrix(y_test, y_pred).tolist()

            # Version string
            version_str = f"{cand['algorithm']}-v{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:4]}"
            artifact_filename = f"{version_str}.joblib"
            artifact_path = os.path.join(models_folder, artifact_filename)

            # Bundle scaler and model together
            bundle = {
                "algorithm": cand["algorithm"],
                "model_name": alg_name,
                "version": version_str,
                "scaler": scaler,
                "model": model_inst,
                "feature_names": feature_names,
                "metrics": {
                    "accuracy": acc,
                    "precision": prec,
                    "recall": rec,
                    "f1_score": f1,
                    "roc_auc": roc_auc,
                    "latency_ms": avg_latency,
                }
            }
            joblib.dump(bundle, artifact_path)

            eval_entry = {
                "name": alg_name,
                "algorithm": cand["algorithm"],
                "version": version_str,
                "artifact_path": artifact_filename,
                "accuracy": acc,
                "precision_score": prec,
                "recall_score": rec,
                "f1_score": f1,
                "roc_auc": roc_auc,
                "confusion_matrix": cm,
                "avg_latency_ms": avg_latency,
                "training_time_sec": train_time,
                "hyperparameters": cand["params"],
            }
            evaluated_results.append(eval_entry)

            # Save Model record to Database
            db_model = MLModel(
                name=alg_name,
                algorithm=cand["algorithm"],
                version=version_str,
                artifact_path=artifact_filename,
                is_active=False,
                feature_names_json=json.dumps(feature_names),
                hyperparameters_json=json.dumps(cand["params"]),
                accuracy=acc,
                precision_score=prec,
                recall_score=rec,
                f1_score=f1,
                roc_auc=roc_auc,
                confusion_matrix_json=json.dumps(cm),
                avg_latency_ms=avg_latency,
                training_time_sec=train_time,
                selection_score=calculate_selection_score(eval_entry, current_app.config),
                selection_notes="Evaluated during training run.",
            )
            db.session.add(db_model)
            created_models.append(db_model)

        db.session.flush()

        # Run automated model selection
        best_candidate, selection_reason = select_best_model(evaluated_results, current_app.config)

        active_model = None
        if best_candidate:
            # Find matching created model
            for m in created_models:
                if m.version == best_candidate["version"]:
                    active_model = m
                    break

            if active_model:
                # Deactivate all other models
                MLModel.query.update({MLModel.is_active: False})
                active_model.is_active = True
                active_model.selection_score = best_candidate.get("selection_score", 0.0)
                active_model.selection_notes = selection_reason
                training_run.model_id = active_model.id
                training_run.selected_model_name = active_model.name

        training_run.status = "completed"
        training_run.evaluated_models_count = len(evaluated_results)
        training_run.evaluation_summary_json = json.dumps(evaluated_results)
        training_run.selection_reason = selection_reason
        training_run.completed_at = datetime.now(timezone.utc)

        # Audit log entry
        audit = AuditLog(
            user_id=initiated_by_id,
            action="MODEL_TRAINING_PIPELINE",
            details=f"Pipeline executed on dataset '{dataset.original_filename}'. Selected: {active_model.name if active_model else 'None'}. Reason: {selection_reason}",
            ip_address="127.0.0.1",
        )
        db.session.add(audit)
        db.session.commit()

        return training_run, active_model

    except Exception as exc:
        db.session.rollback()
        training_run.status = "failed"
        training_run.error_message = str(exc)
        training_run.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        raise exc


def activate_specific_model(model_id: int, user_id: int = None) -> MLModel:
    """Manually activate a specific trained model by administrator request."""
    model = db.session.get(MLModel, model_id)
    if not model:
        raise ValueError(f"Model ID {model_id} not found.")

    MLModel.query.update({MLModel.is_active: False})
    model.is_active = True
    model.selection_notes = f"Manually activated by administrator at {datetime.now(timezone.utc).isoformat()} UTC."
    
    audit = AuditLog(
        user_id=user_id,
        action="MANUAL_MODEL_ACTIVATION",
        details=f"Model '{model.name}' version '{model.version}' manually activated.",
        ip_address="127.0.0.1"
    )
    db.session.add(audit)
    db.session.commit()
    return model

"""Prediction and Inference Engine for URL Scanning.

Executes real-time lexical inference using active serialized model pipelines,
computes risk scores and categories, provides explainability breakdown,
and persists scan results with features in MySQL.
"""
import hashlib
import os
import time
from datetime import datetime
import joblib
import numpy as np
from flask import current_app

from app.extensions import db
from app.models import Scan, ScanFeature, MLModel
from app.ml.feature_extraction import extract_features, FEATURE_NAMES

# Cached model bundle in memory for ultra-fast repeated inference
_CACHED_MODEL_BUNDLE = None
_CACHED_MODEL_VERSION = None


def get_risk_category(risk_score: float) -> str:
    """Classify numerical risk score into documented risk category."""
    if risk_score < 25.0:
        return "Low"
    elif risk_score < 55.0:
        return "Moderate"
    elif risk_score < 80.0:
        return "High"
    else:
        return "Critical"


def load_active_model() -> tuple[dict | None, MLModel | None]:
    """Retrieve the currently active model record and loaded artifact bundle."""
    global _CACHED_MODEL_BUNDLE, _CACHED_MODEL_VERSION

    active_record = MLModel.query.filter_by(is_active=True).first()
    if not active_record:
        # Fallback to most recently trained model if none explicitly active
        active_record = MLModel.query.order_by(MLModel.created_at.desc()).first()

    if not active_record:
        return None, None

    if _CACHED_MODEL_BUNDLE and _CACHED_MODEL_VERSION == active_record.version:
        return _CACHED_MODEL_BUNDLE, active_record

    models_folder = current_app.config["MODELS_FOLDER"]
    artifact_full_path = os.path.join(models_folder, active_record.artifact_path)

    if not os.path.exists(artifact_full_path):
        return None, active_record

    try:
        bundle = joblib.load(artifact_full_path)
        _CACHED_MODEL_BUNDLE = bundle
        _CACHED_MODEL_VERSION = active_record.version
        return bundle, active_record
    except Exception:
        return None, active_record


def predict_url(raw_url: str, user_id: int) -> tuple[Scan, dict]:
    """Analyze a URL, execute ML model inference, persist scan + features, and return structured output."""
    t_start = time.perf_counter()

    # 1. Lexical feature extraction (safe, zero network interaction)
    extracted = extract_features(raw_url)
    features_dict = extracted["features"]
    explanation = extracted["explanation"]
    normalized_url = extracted["normalized_url"]

    # Vector in exact training order
    feature_vector = np.array([[features_dict[name] for name in FEATURE_NAMES]], dtype=float)

    # 2. Load active model
    bundle, model_record = load_active_model()

    if bundle and "scaler" in bundle and "model" in bundle:
        scaler = bundle["scaler"]
        model = bundle["model"]
        version_name = f"{bundle.get('model_name', 'Model')} ({bundle.get('version', 'v1.0')})"
        model_id = model_record.id if model_record else None

        # Transform features
        scaled_vector = scaler.transform(feature_vector)
        pred_label_num = int(model.predict(scaled_vector)[0])

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(scaled_vector)[0]
            # probability of phishing (class 1)
            phishing_prob = float(probs[1]) if len(probs) > 1 else (1.0 if pred_label_num == 1 else 0.0)
        else:
            phishing_prob = 0.95 if pred_label_num == 1 else 0.05
    else:
        # Fallback heuristic if no model trained yet (safe academic default)
        version_name = "Baseline Heuristic Engine v1.0"
        model_id = None
        suspicious_score = (
            features_dict["suspicious_token_count"] * 25 +
            features_dict["is_ip"] * 40 +
            features_dict["has_at_symbol"] * 30 +
            (15 if features_dict["num_dots"] >= 4 else 0)
        )
        phishing_prob = min(max(suspicious_score / 100.0, 0.05), 0.99)
        pred_label_num = 1 if phishing_prob >= 0.50 else 0

    prediction_label = "phishing" if pred_label_num == 1 else "legitimate"
    risk_score = round(phishing_prob * 100.0, 1)
    risk_category = get_risk_category(risk_score)

    t_latency = round((time.perf_counter() - t_start) * 1000.0, 2)

    # Key risk indicators for user transparency
    indicators = []
    if features_dict["is_ip"]:
        indicators.append("Host is an IP address instead of a domain name (high phishing risk).")
    if features_dict["has_at_symbol"]:
        indicators.append("Contains '@' symbol which can disguise target destination.")
    if explanation["detected_tokens"]:
        indicators.append(f"Contains security-sensitive tokens: {', '.join(explanation['detected_tokens'])}.")
    if features_dict["num_subdomains"] >= 2:
        indicators.append(f"Excessive subdomains detected ({features_dict['num_subdomains']}).")
    if features_dict["num_dots"] >= 4:
        indicators.append(f"High number of dots in URL structure ({features_dict['num_dots']}).")
    if features_dict["is_https"] == 0:
        indicators.append("Lacks HTTPS encryption (unsecured protocol).")
    elif features_dict["is_https"] == 1 and prediction_label == "phishing":
        indicators.append("Note: Uses HTTPS encryption, but lexical patterns match phishing (HTTPS does NOT imply safety).")

    explanation["risk_indicators"] = indicators
    explanation["risk_score"] = risk_score
    explanation["risk_category"] = risk_category
    explanation["probability"] = round(phishing_prob, 4)

    # 3. Persist Scan Record
    url_hash = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()

    scan = Scan(
        user_id=user_id,
        url=normalized_url,
        url_hash=url_hash,
        prediction_label=prediction_label,
        risk_score=risk_score,
        risk_category=risk_category,
        probability=round(phishing_prob, 4),
        model_version=version_name,
        model_id=model_id,
        latency_ms=t_latency,
        explanation_json=None,
    )
    scan.explanation = explanation
    db.session.add(scan)
    db.session.flush()

    # 4. Persist Features (1-to-1)
    scan_feature = ScanFeature(
        scan_id=scan.id,
        url_length=features_dict["url_length"],
        hostname_length=features_dict["hostname_length"],
        num_dots=features_dict["num_dots"],
        num_hyphens=features_dict["num_hyphens"],
        num_digits=features_dict["num_digits"],
        num_subdomains=features_dict["num_subdomains"],
        is_https=features_dict["is_https"],
        is_ip=features_dict["is_ip"],
        suspicious_token_count=features_dict["suspicious_token_count"],
        path_length=features_dict["path_length"],
        query_length=features_dict["query_length"],
        has_at_symbol=features_dict["has_at_symbol"],
        percent_encoded_count=features_dict["percent_encoded_count"],
    )
    db.session.add(scan_feature)
    db.session.commit()

    return scan, explanation

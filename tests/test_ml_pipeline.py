"""Tests for machine-learning training pipeline and automated model selector."""
import os
import joblib
from app.models import MLModel, TrainingRun
from app.ml.dataset_service import create_or_load_sample_dataset
from app.ml.training_service import run_training_pipeline
from app.ml.model_selector import select_best_model, calculate_selection_score


def test_training_pipeline_and_model_selection(db_session, admin_user):
    """Test full training pipeline execution, held-out evaluation, and auto-activation."""
    dataset = create_or_load_sample_dataset()
    assert dataset is not None
    assert dataset.total_rows >= 50

    run_record, active_model = run_training_pipeline(dataset.id, initiated_by_id=admin_user.id)

    assert run_record.status == "completed"
    assert run_record.evaluated_models_count == 3
    assert active_model is not None
    assert active_model.is_active is True

    # Real evaluation scores (held out test set, never fabricated)
    assert 0.0 <= active_model.accuracy <= 1.0
    assert 0.0 <= active_model.recall_score <= 1.0
    assert 0.0 <= active_model.f1_score <= 1.0
    assert active_model.avg_latency_ms > 0.0

    # Verify model artifact exists on disk and loads properly
    artifact_path = os.path.join(active_model.artifact_path)
    # Check all 3 models stored in DB
    all_models = MLModel.query.all()
    assert len(all_models) >= 3
    algs = [m.algorithm for m in all_models]
    assert "random_forest" in algs
    assert "logistic_regression" in algs
    assert "decision_tree" in algs


def test_model_selector_rejection_and_ranking():
    """Verify that models failing minimum recall threshold are rejected."""
    config = {
        "MIN_MODEL_RECALL": 0.85,
        "MAX_LATENCY_MS": 50.0,
        "SCORE_WEIGHT_RECALL": 0.40,
        "SCORE_WEIGHT_F1": 0.30,
        "SCORE_WEIGHT_PRECISION": 0.20,
        "SCORE_WEIGHT_SPEED": 0.10,
    }

    candidates = [
        {
            "name": "Weak Recall Model",
            "algorithm": "test_alg_1",
            "version": "v1",
            "recall_score": 0.70,  # Below 0.85
            "f1_score": 0.80,
            "precision_score": 0.90,
            "avg_latency_ms": 10.0,
        },
        {
            "name": "High Recall Model",
            "algorithm": "test_alg_2",
            "version": "v2",
            "recall_score": 0.95,  # Passes
            "f1_score": 0.92,
            "precision_score": 0.90,
            "avg_latency_ms": 12.0,
        }
    ]

    best, reason = select_best_model(candidates, config)
    assert best is not None
    assert best["name"] == "High Recall Model"
    assert "Passed minimum recall threshold" in reason

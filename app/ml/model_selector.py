"""Automatic Algorithm Selector and Evaluator.

Applies configurable validation criteria, rejects models failing recall or latency thresholds,
and calculates composite ranking scores with deterministic tie-breaking.
"""
from flask import current_app


def calculate_selection_score(metrics: dict, config: dict = None) -> float:
    """Calculate weighted composite score balancing detection recall, F1, precision, and latency.
    
    Formula:
        Score = (W_recall * Recall) + (W_f1 * F1) + (W_prec * Precision) + (W_speed * SpeedFactor)
    Where:
        SpeedFactor = max(0.0, 1.0 - (latency_ms / max_latency_ms))
    """
    if config is None:
        config = current_app.config

    w_recall = config.get("SCORE_WEIGHT_RECALL", 0.40)
    w_f1 = config.get("SCORE_WEIGHT_F1", 0.30)
    w_prec = config.get("SCORE_WEIGHT_PRECISION", 0.20)
    w_speed = config.get("SCORE_WEIGHT_SPEED", 0.10)
    max_latency = config.get("MAX_LATENCY_MS", 100.0)

    recall = float(metrics.get("recall_score", 0.0))
    f1 = float(metrics.get("f1_score", 0.0))
    precision = float(metrics.get("precision_score", 0.0))
    latency = float(metrics.get("avg_latency_ms", 5.0))

    speed_factor = max(0.0, 1.0 - (latency / max_latency)) if max_latency > 0 else 1.0

    composite = (w_recall * recall) + (w_f1 * f1) + (w_prec * precision) + (w_speed * speed_factor)
    return round(float(composite), 4)


def select_best_model(evaluated_candidates: list, config: dict = None) -> tuple[dict | None, str]:
    """Select the optimal model among candidate evaluation results.
    
    Returns:
        (best_candidate_dict, selection_reason)
    """
    if not evaluated_candidates:
        return None, "No candidate models were successfully evaluated."

    if config is None:
        config = current_app.config

    min_recall = config.get("MIN_MODEL_RECALL", 0.80)
    max_latency = config.get("MAX_LATENCY_MS", 100.0)

    eligible = []
    rejected_reasons = []

    for candidate in evaluated_candidates:
        name = candidate["name"]
        rec = candidate["recall_score"]
        lat = candidate["avg_latency_ms"]

        if rec < min_recall:
            rejected_reasons.append(f"{name} rejected: Recall ({rec:.3f}) below threshold ({min_recall:.3f}).")
            continue
        if lat > max_latency:
            rejected_reasons.append(f"{name} rejected: Latency ({lat:.2f}ms) exceeded threshold ({max_latency:.2f}ms).")
            continue

        candidate["selection_score"] = calculate_selection_score(candidate, config)
        eligible.append(candidate)

    if not eligible:
        reason = "All candidates failed minimum validation thresholds: " + "; ".join(rejected_reasons)
        return None, reason

    # Sort deterministically:
    # 1. Higher composite selection score
    # 2. Higher recall (cybersecurity priority: minimize false negatives)
    # 3. Higher F1 score
    # 4. Lower latency
    eligible.sort(
        key=lambda m: (
            m["selection_score"],
            m["recall_score"],
            m["f1_score"],
            -m["avg_latency_ms"]
        ),
        reverse=True
    )

    best = eligible[0]
    reason = (
        f"Selected '{best['name']}' based on highest composite score ({best['selection_score']:.4f}) "
        f"[Recall: {best['recall_score']:.4f}, F1: {best['f1_score']:.4f}, Precision: {best['precision_score']:.4f}, Latency: {best['avg_latency_ms']:.2f}ms]. "
        f"Passed minimum recall threshold ({min_recall:.2f}) and latency ceiling ({max_latency:.1f}ms)."
    )

    return best, reason

"""Local, privacy-minimized evaluation of labeled detection artifacts.

The package keeps the historical `agent_traffic_intelligence.evaluation` import surface:
the metric and manifest API is re-exported from `metrics`. Controlled-campaign planning
lives in `evaluation.campaign`, and the ATI-PF-2 session protocol, baseline ladder and
warehouse export live in `evaluation.pf2`. Import those submodules explicitly; this
initialiser deliberately does not load them.
"""

from agent_traffic_intelligence.evaluation.metrics import (
    AutomationEvaluation,
    EvaluationError,
    evaluate_automation_scores,
    evaluate_stratified_automation_scores,
    expected_calibration_error,
    pr_auc,
    validate_corpus_manifest,
)

__all__ = [
    "AutomationEvaluation",
    "EvaluationError",
    "evaluate_automation_scores",
    "evaluate_stratified_automation_scores",
    "expected_calibration_error",
    "pr_auc",
    "validate_corpus_manifest",
]

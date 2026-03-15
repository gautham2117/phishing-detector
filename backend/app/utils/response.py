# response.py
# Every API endpoint in this project returns JSON using this exact schema.
# Consistency here is critical: the dashboard JS and Chrome extension
# both expect this exact structure in every response.

from datetime import datetime


def build_response(
    status: str,
    risk_score: float,
    label: str,
    module_results: dict,
    explanation: str,
    recommended_action: str
) -> dict:
    """
    Build the standard JSON response for every scan result.

    Args:
        status:             "success" | "error" | "partial"
        risk_score:         float 0.0–100.0
        label:              "SAFE" | "SUSPICIOUS" | "MALICIOUS"
        module_results:     dict where keys are module names,
                            values are their individual findings
        explanation:        plain-language string (from BART or rule summary)
        recommended_action: "ALLOW" | "WARN" | "QUARANTINE" | "BLOCK"

    Returns:
        A dict that Flask/FastAPI will serialize to JSON.
    """

    return {
        "status":             status,
        "risk_score":         round(risk_score, 2),
        "label":              label,
        "module_results":     module_results,
        "explanation":        explanation,
        "recommended_action": recommended_action,
        "timestamp":          datetime.utcnow().isoformat() + "Z"
    }


def error_response(message: str) -> dict:
    """Return a standard error response when a scan fails."""
    return build_response(
        status="error",
        risk_score=0.0,
        label="UNKNOWN",
        module_results={},
        explanation=message,
        recommended_action="WARN"
    )
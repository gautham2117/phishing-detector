# detection_rules.py
import time
import logging
import requests
from flask import (
    Blueprint, render_template, request,
    jsonify, current_app
)
from backend.app.database import db
from backend.app.auth import role_required
from backend.modules.rule_engine import analyze_url_rules

logger   = logging.getLogger(__name__)
rules_bp = Blueprint("rules_bp", __name__)

# ── Analytics cache (module-level, 60-second TTL) ─────────────────────────────
_analytics_cache: dict = {}   # {"data": dict, "ts": float}
_ANALYTICS_TTL = 60           # seconds


def _api():
    return current_app.config.get("FASTAPI_BASE_URL", "http://127.0.0.1:8001")


# ─────────────────────────────────────────────────────────────────────────────
# Existing routes — unchanged
# ─────────────────────────────────────────────────────────────────────────────

@rules_bp.route("/rules", methods=["GET"])
@role_required("admin", "analyst")
def detection_rules_page():
    all_rules = []
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        if resp.status_code == 200:
            all_rules = resp.json().get("rules", [])
    except Exception:
        pass
    return render_template("detection_rules.html", all_rules=all_rules)


@rules_bp.route("/rules/scan/url", methods=["POST"])
@role_required("admin", "analyst")
def scan_url_rules():
    data = request.get_json() or {}
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        resp = requests.post(
            f"{_api()}/api/scan/rules/url",
            json={"url": url},
            timeout=30
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@rules_bp.route("/rules/scan/email", methods=["POST"])
@role_required("admin", "analyst")
def scan_email_rules():
    data = request.get_json() or {}
    try:
        resp = requests.post(
            f"{_api()}/api/scan/rules/email",
            json={
                "subject":   data.get("subject",   ""),
                "body_text": data.get("body_text", ""),
                "body_html": data.get("body_html", ""),
                "urls":      data.get("urls",      [])
            },
            timeout=30
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to FastAPI"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@rules_bp.route("/rules/list", methods=["GET"])
@role_required("admin", "analyst")
def get_rules_list():
    try:
        resp = requests.get(f"{_api()}/api/rules/list", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# NEW: GET /rules/analytics
# ─────────────────────────────────────────────────────────────────────────────

@rules_bp.route("/rules/analytics", methods=["GET"])
@role_required("admin", "analyst")
def rules_analytics():
    """
    Re-run analyze_url_rules() on the last 50 stored URLScan records and
    aggregate which rule IDs fire most frequently.

    Response:
    {
        "rule_frequency": [
            {
                "rule_id":      str,
                "name":         str,
                "severity":     str,
                "hit_count":    int,
                "hit_rate_pct": float   # percentage of URLs that triggered it
            },
            ...  (sorted by hit_count desc)
        ],
        "total_urls_analyzed": int,
        "analyzed_at":         str   (ISO timestamp)
    }

    Result is cached for 60 seconds to avoid expensive recomputation.
    """
    global _analytics_cache

    # ── Return cached result if still fresh ───────────────────────────────
    now = time.time()
    if _analytics_cache and (now - _analytics_cache.get("ts", 0)) < _ANALYTICS_TTL:
        return jsonify(_analytics_cache["data"])

    # ── Pull last 50 URLScan rows ─────────────────────────────────────────
    try:
        from backend.app.models import URLScan
        rows = (
            URLScan.query
            .order_by(URLScan.id.desc())
            .limit(50)
            .all()
        )
    except Exception as e:
        logger.error("Analytics DB query failed: %s", e)
        return jsonify({"error": f"DB query failed: {str(e)}"}), 500

    if not rows:
        result = {
            "rule_frequency":       [],
            "total_urls_analyzed":  0,
            "analyzed_at":          _iso_now(),
        }
        _analytics_cache = {"data": result, "ts": now}
        return jsonify(result)

    # ── Re-run rule engine on each URL ────────────────────────────────────
    # Accumulate hit counts and rule metadata keyed by rule_id
    hit_counts  = {}   # rule_id → int
    rule_meta   = {}   # rule_id → {name, severity}
    total_urls  = len(rows)

    for row in rows:
        # Prefer the normalised URL; fall back to raw_url
        url_str = (row.normalized_url or row.raw_url or "").strip()
        if not url_str:
            total_urls -= 1
            continue

        try:
            result = analyze_url_rules(url_str)
        except Exception as exc:
            logger.warning("Rule engine error for %s: %s", url_str[:60], exc)
            total_urls -= 1
            continue

        for hit in result.get("hits", []):
            rid  = hit.get("rule_id", "")
            if not rid:
                continue
            hit_counts[rid] = hit_counts.get(rid, 0) + 1
            if rid not in rule_meta:
                rule_meta[rid] = {
                    "name":     hit.get("name",     rid),
                    "severity": hit.get("severity", "MEDIUM"),
                }

    # ── Build sorted frequency list ───────────────────────────────────────
    freq_list = []
    for rid, count in hit_counts.items():
        meta = rule_meta.get(rid, {"name": rid, "severity": "MEDIUM"})
        hit_rate = round((count / total_urls * 100), 1) if total_urls > 0 else 0.0
        freq_list.append({
            "rule_id":      rid,
            "name":         meta["name"],
            "severity":     meta["severity"],
            "hit_count":    count,
            "hit_rate_pct": hit_rate,
        })

    # Sort by hit_count descending
    freq_list.sort(key=lambda x: x["hit_count"], reverse=True)

    result = {
        "rule_frequency":      freq_list,
        "total_urls_analyzed": total_urls,
        "analyzed_at":         _iso_now(),
    }

    # ── Cache and return ──────────────────────────────────────────────────
    _analytics_cache = {"data": result, "ts": now}
    return jsonify(result)


def _iso_now() -> str:
    from datetime import datetime
    return datetime.utcnow().isoformat() + "Z"
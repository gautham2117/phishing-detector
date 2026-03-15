"""
backend/modules/alert_engine.py
Phase 13 — Alerting & Audit System Engine
Handles alert generation, BART summarization, severity assignment,
audit logging, CSV export, and PDF report generation.
"""

import csv
import io
import json
import logging
import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── Severity thresholds ────────────────────────────────────────────────────────
def assign_severity(risk_score: float) -> str:
    if risk_score >= 80:
        return "Critical"
    if risk_score >= 60:
        return "High"
    if risk_score >= 35:
        return "Medium"
    return "Low"


# ── Verdict filter — only alert on these ──────────────────────────────────────
ALERT_VERDICTS = {"SUSPICIOUS", "MALICIOUS", "PHISHING", "AI_GENERATED",
                  "HIGH", "CRITICAL", "MIXED"}


# ══════════════════════════════════════════════════════════════════════════════
# BART THREAT SUMMARIZER
# ══════════════════════════════════════════════════════════════════════════════

def generate_threat_summary(findings: dict, verdict: str,
                             risk_score: float, module: str) -> str:
    """
    Use BART (facebook/bart-large-cnn, loaded as 'threat_summarizer')
    to generate a 1–2 sentence human-readable threat summary.
    Falls back to a rule-based summary if model is unavailable.
    """
    try:
        from backend.ml.model_loader import get_model
        pipeline = get_model("threat_summarizer")
        if pipeline is None:
            raise RuntimeError("threat_summarizer model not loaded")

        # Build a structured text block for BART to summarise
        lines = [
            f"Module: {module}.",
            f"Verdict: {verdict}.",
            f"Risk score: {risk_score}/100.",
        ]

        for key, val in findings.items():
            if isinstance(val, list) and val:
                lines.append(f"{key}: {', '.join(str(v) for v in val[:5])}.")
            elif isinstance(val, dict) and val:
                for k, v in list(val.items())[:3]:
                    lines.append(f"{k}: {v}.")
            elif val:
                lines.append(f"{key}: {val}.")

        input_text = " ".join(lines)[:1024]

        output = pipeline(
            input_text,
            max_length=80,
            min_length=20,
            do_sample=False,
        )

        if isinstance(output, list) and output:
            return output[0].get("summary_text", "").strip()
        return _rule_based_summary(verdict, risk_score, module, findings)

    except Exception as ex:
        logger.warning("BART summarization failed: %s", ex)
        return _rule_based_summary(verdict, risk_score, module, findings)


def _rule_based_summary(verdict: str, risk_score: float,
                         module: str, findings: dict) -> str:
    """Fallback summary when BART is unavailable."""
    sev  = assign_severity(risk_score)
    base = (
        f"{sev} severity {verdict.lower()} detected by {module} module "
        f"with risk score {risk_score:.1f}/100."
    )
    extras = []
    if findings.get("yara_matches"):
        extras.append(
            f"YARA rules matched: {', '.join(findings['yara_matches'][:3])}"
        )
    if findings.get("suspicious_strings"):
        extras.append(
            f"Suspicious patterns found: "
            f"{', '.join(findings['suspicious_strings'][:3])}"
        )
    if findings.get("detected_brands"):
        extras.append(
            f"Brand spoofing detected: "
            f"{', '.join(findings['detected_brands'][:3])}"
        )
    if findings.get("phishing_keywords"):
        extras.append(
            f"Phishing keywords present: "
            f"{', '.join(findings['phishing_keywords'][:3])}"
        )
    if extras:
        return base + " " + "; ".join(extras) + "."
    return base


# ══════════════════════════════════════════════════════════════════════════════
# ALERT CREATION
# ══════════════════════════════════════════════════════════════════════════════

def create_alert(
    module:             str,
    input_type:         str,
    scan_id:            Optional[int],
    risk_score:         float,
    verdict:            str,
    recommended_action: str,
    triggered_rules:    list = None,
    ml_verdicts:        dict = None,
    raw_findings:       dict = None,
    actor:              str  = "system",
) -> Optional[int]:
    """
    Create one Alert row and write an AuditLog entry.
    Returns the new alert ID or None on error.
    """
    # Only alert on suspicious/malicious verdicts
    if verdict.upper() not in ALERT_VERDICTS and risk_score < 35:
        return None

    try:
        from backend.app.database import db
        from backend.app.models   import Alert

        severity = assign_severity(risk_score)
        findings = raw_findings or {}

        threat_summary = generate_threat_summary(
            findings, verdict, risk_score, module
        )

        alert = Alert(
            module             = module[:50],
            input_type         = input_type[:30],
            scan_id            = scan_id,
            risk_score         = risk_score,
            severity           = severity,
            verdict            = verdict[:30],
            triggered_rules    = json.dumps(triggered_rules or []),
            ml_verdicts        = json.dumps(ml_verdicts    or {}),
            recommended_action = recommended_action[:30],
            threat_summary     = threat_summary,
            raw_findings       = json.dumps(findings),
            status             = "open",
            created_at         = datetime.datetime.utcnow(),
        )
        db.session.add(alert)
        db.session.flush()

        _audit(
            action    = "ALERT_CREATED",
            actor     = actor,
            module    = module,
            object_id = alert.id,
            detail    = json.dumps({
                "verdict":   verdict,
                "severity":  severity,
                "risk_score":risk_score,
                "scan_id":   scan_id,
            }),
        )

        db.session.commit()
        return alert.id

    except Exception as ex:
        try:
            from backend.app.database import db
            db.session.rollback()
        except Exception:
            pass
        logger.error("create_alert error: %s", ex)
        return None


def get_alerts(
    severity:   Optional[str] = None,
    module:     Optional[str] = None,
    status:     Optional[str] = None,
    date_from:  Optional[str] = None,
    date_to:    Optional[str] = None,
    limit:      int           = 100,
) -> list:
    """Return alerts with optional filters."""
    try:
        from backend.app.models import Alert
        query = Alert.query

        if severity:
            query = query.filter(Alert.severity == severity)
        if module:
            query = query.filter(Alert.module == module)
        if status:
            query = query.filter(Alert.status == status)
        if date_from:
            try:
                dt = datetime.datetime.fromisoformat(date_from)
                query = query.filter(Alert.created_at >= dt)
            except Exception:
                pass
        if date_to:
            try:
                dt = datetime.datetime.fromisoformat(date_to)
                query = query.filter(Alert.created_at <= dt)
            except Exception:
                pass

        rows = query.order_by(Alert.created_at.desc()).limit(limit).all()
        return [_serialize_alert(r) for r in rows]

    except Exception as ex:
        logger.error("get_alerts error: %s", ex)
        return []


def get_alert_detail(alert_id: int) -> Optional[dict]:
    """Return full detail for one alert."""
    try:
        from backend.app.models import Alert
        r = Alert.query.get(alert_id)
        if r is None:
            return None
        return _serialize_alert(r, full=True)
    except Exception as ex:
        logger.error("get_alert_detail error: %s", ex)
        return None


def acknowledge_alert(alert_id: int,
                      actor: str = "admin") -> dict:
    """Mark an alert as acknowledged."""
    try:
        from backend.app.database import db
        from backend.app.models   import Alert

        alert = Alert.query.get(alert_id)
        if alert is None:
            return {"error": "Alert not found."}
        if alert.status != "open":
            return {"error": f"Alert is already {alert.status}."}

        alert.status           = "acknowledged"
        alert.acknowledged_by  = actor[:100]
        alert.acknowledged_at  = datetime.datetime.utcnow()

        _audit(
            action    = "ALERT_ACKNOWLEDGED",
            actor     = actor,
            module    = alert.module,
            object_id = alert_id,
            detail    = json.dumps({"previous_status": "open"}),
        )

        db.session.commit()
        return {"status": "success", "alert_id": alert_id,
                "new_status": "acknowledged"}

    except Exception as ex:
        try:
            from backend.app.database import db
            db.session.rollback()
        except Exception:
            pass
        logger.error("acknowledge_alert error: %s", ex)
        return {"error": str(ex)}


def dismiss_alert(alert_id: int,
                  reason: str = "",
                  actor:  str = "admin") -> dict:
    """Mark an alert as dismissed with an optional reason."""
    try:
        from backend.app.database import db
        from backend.app.models   import Alert

        alert = Alert.query.get(alert_id)
        if alert is None:
            return {"error": "Alert not found."}

        alert.status         = "dismissed"
        alert.dismiss_reason = reason[:500]

        _audit(
            action    = "ALERT_DISMISSED",
            actor     = actor,
            module    = alert.module,
            object_id = alert_id,
            detail    = json.dumps({"reason": reason}),
        )

        db.session.commit()
        return {"status": "success", "alert_id": alert_id,
                "new_status": "dismissed"}

    except Exception as ex:
        try:
            from backend.app.database import db
            db.session.rollback()
        except Exception:
            pass
        logger.error("dismiss_alert error: %s", ex)
        return {"error": str(ex)}


def _serialize_alert(r, full: bool = False) -> dict:
    try:
        triggered_rules = json.loads(r.triggered_rules or "[]")
    except Exception:
        triggered_rules = []
    try:
        ml_verdicts = json.loads(r.ml_verdicts or "{}")
    except Exception:
        ml_verdicts = {}

    base = {
        "id":                 r.id,
        "module":             r.module,
        "input_type":         r.input_type,
        "scan_id":            r.scan_id,
        "risk_score":         r.risk_score,
        "severity":           r.severity,
        "verdict":            r.verdict,
        "recommended_action": r.recommended_action,
        "threat_summary":     r.threat_summary,
        "status":             r.status,
        "acknowledged_by":    r.acknowledged_by,
        "acknowledged_at":    (
            r.acknowledged_at.isoformat() + "Z"
            if r.acknowledged_at else None
        ),
        "created_at":         (
            r.created_at.isoformat() + "Z"
            if r.created_at else ""
        ),
        "triggered_rules":    triggered_rules,
        "ml_verdicts":        ml_verdicts,
    }
    if full:
        try:
            base["raw_findings"] = json.loads(r.raw_findings or "{}")
        except Exception:
            base["raw_findings"] = {}
        base["dismiss_reason"] = r.dismiss_reason
    return base


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

def _audit(action: str, actor: str = "system",
           module: str = "", object_id: Optional[int] = None,
           detail: str = "", ip_address: str = "") -> None:
    """
    Append one immutable audit log entry.
    Never raises — failures are logged silently.
    """
    try:
        from backend.app.database import db
        from backend.app.models   import AuditLog

        log = AuditLog(
            action     = action[:80],
            actor      = actor[:100],
            module     = module[:50],
            object_id  = object_id,
            detail     = detail[:2000],
            ip_address = ip_address[:60],
            created_at = datetime.datetime.utcnow(),
        )
        db.session.add(log)
        # Note: caller is responsible for commit
    except Exception as ex:
        logger.warning("_audit write error: %s", ex)


def get_audit_log(limit: int = 100) -> list:
    """Return recent audit log entries."""
    try:
        from backend.app.models import AuditLog
        rows = (
            AuditLog.query
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id":         r.id,
                "action":     r.action,
                "actor":      r.actor,
                "module":     r.module,
                "object_id":  r.object_id,
                "detail":     r.detail,
                "ip_address": r.ip_address,
                "created_at": (
                    r.created_at.isoformat() + "Z"
                    if r.created_at else ""
                ),
            }
            for r in rows
        ]
    except Exception as ex:
        logger.error("get_audit_log error: %s", ex)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# CSV EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def export_alerts_csv(
    severity:  Optional[str] = None,
    module:    Optional[str] = None,
    status:    Optional[str] = None,
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
) -> bytes:
    """
    Export filtered alerts as CSV bytes.
    """
    try:
        alerts = get_alerts(
            severity=severity,
            module=module,
            status=status,
            date_from=date_from,
            date_to=date_to,
            limit=10000,
        )

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "ID", "Module", "Input Type", "Scan ID", "Risk Score",
            "Severity", "Verdict", "Recommended Action",
            "Threat Summary", "Status", "Acknowledged By",
            "Triggered Rules", "Created At",
        ])

        for a in alerts:
            rules = (
                ", ".join(a["triggered_rules"])
                if a["triggered_rules"] else ""
            )
            writer.writerow([
                a["id"],
                a["module"],
                a["input_type"],
                a["scan_id"] or "",
                a["risk_score"],
                a["severity"],
                a["verdict"],
                a["recommended_action"],
                a["threat_summary"],
                a["status"],
                a["acknowledged_by"] or "",
                rules,
                a["created_at"],
            ])

        return output.getvalue().encode("utf-8")

    except Exception as ex:
        logger.error("export_alerts_csv error: %s", ex)
        return b""


# ══════════════════════════════════════════════════════════════════════════════
# PDF EXPORT (single alert)
# ══════════════════════════════════════════════════════════════════════════════

def export_alert_pdf(alert_id: int) -> bytes:
    """
    Generate a PDF report for a single alert.
    Uses ReportLab if available, falls back to plain HTML bytes.
    """
    alert = get_alert_detail(alert_id)
    if not alert:
        return b""

    try:
        from reportlab.lib.pagesizes  import A4
        from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units      import cm
        from reportlab.lib             import colors
        from reportlab.platypus       import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable,
        )

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm,   bottomMargin=2*cm,
        )

        styles  = getSampleStyleSheet()
        story   = []

        # ── Title ──────────────────────────────────────────────────────────
        title_style = ParagraphStyle(
            "title",
            parent    = styles["Heading1"],
            fontSize  = 18,
            textColor = colors.HexColor("#388bfd"),
            spaceAfter= 6,
        )
        story.append(Paragraph("PhishGuard — Alert Report", title_style))
        story.append(Paragraph(
            f"Alert ID #{alert['id']} · Generated {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
            styles["Normal"]
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#30363d")))
        story.append(Spacer(1, 0.3*cm))

        # ── Severity badge row ─────────────────────────────────────────────
        sev_colors = {
            "Critical": "#f85149",
            "High":     "#d29922",
            "Medium":   "#388bfd",
            "Low":      "#3fb950",
        }
        sev_color = sev_colors.get(alert["severity"], "#8b949e")
        sev_style = ParagraphStyle(
            "sev",
            parent    = styles["Normal"],
            fontSize  = 13,
            textColor = colors.HexColor(sev_color),
            fontName  = "Helvetica-Bold",
        )
        story.append(Paragraph(
            f"Severity: {alert['severity']}  ·  "
            f"Verdict: {alert['verdict']}  ·  "
            f"Risk Score: {alert['risk_score']:.1f}/100",
            sev_style,
        ))
        story.append(Spacer(1, 0.3*cm))

        # ── Core details table ─────────────────────────────────────────────
        core_data = [
            ["Field",              "Value"],
            ["Module",             alert["module"]],
            ["Input Type",         alert["input_type"]],
            ["Scan ID",            str(alert["scan_id"] or "—")],
            ["Recommended Action", alert["recommended_action"]],
            ["Status",             alert["status"]],
            ["Created At",         alert["created_at"]],
        ]
        t = Table(core_data, colWidths=[5*cm, 12*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#21262d")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.HexColor("#388bfd")),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#161b22"), colors.HexColor("#0f1117")]),
            ("TEXTCOLOR",   (0, 1), (-1,-1), colors.HexColor("#e6edf3")),
            ("GRID",        (0, 0), (-1,-1), 0.5, colors.HexColor("#30363d")),
            ("TOPPADDING",  (0, 0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

        # ── Threat Summary ─────────────────────────────────────────────────
        story.append(Paragraph("Threat Summary (AI-Generated)", styles["Heading3"]))
        story.append(Paragraph(
            alert["threat_summary"] or "No summary available.",
            styles["Normal"]
        ))
        story.append(Spacer(1, 0.3*cm))

        # ── Triggered rules ────────────────────────────────────────────────
        if alert["triggered_rules"]:
            story.append(Paragraph("Triggered Rules", styles["Heading3"]))
            for rule in alert["triggered_rules"]:
                story.append(Paragraph(f"• {rule}", styles["Normal"]))
            story.append(Spacer(1, 0.3*cm))

        # ── ML verdicts ────────────────────────────────────────────────────
        if alert["ml_verdicts"]:
            story.append(Paragraph("ML Model Verdicts", styles["Heading3"]))
            for model, verdict in alert["ml_verdicts"].items():
                story.append(Paragraph(
                    f"• {model}: {verdict}", styles["Normal"]
                ))
            story.append(Spacer(1, 0.3*cm))

        # ── Raw findings ───────────────────────────────────────────────────
        raw = alert.get("raw_findings", {})
        if raw:
            story.append(Paragraph("Raw Findings", styles["Heading3"]))
            for k, v in list(raw.items())[:10]:
                if v:
                    story.append(Paragraph(
                        f"• {k}: {str(v)[:120]}", styles["Normal"]
                    ))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        logger.warning("ReportLab not installed — falling back to HTML PDF")
        return _html_pdf_fallback(alert)
    except Exception as ex:
        logger.error("export_alert_pdf error: %s", ex)
        return _html_pdf_fallback(alert)


def _html_pdf_fallback(alert: dict) -> bytes:
    """Plain HTML fallback when ReportLab is not available."""
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Alert Report #{alert['id']}</title>
<style>
  body {{ font-family: Arial, sans-serif; padding: 24px; color: #111; }}
  h1   {{ color: #388bfd; }}
  table{{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
  td, th {{ border: 1px solid #ddd; padding: 8px; font-size: 13px; }}
  th   {{ background: #f0f0f0; }}
  .summary {{ background: #f9f9f9; padding: 12px; border-left: 4px solid #388bfd; }}
</style>
</head>
<body>
<h1>PhishGuard — Alert Report #{alert['id']}</h1>
<p>Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC</p>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Module</td><td>{alert['module']}</td></tr>
  <tr><td>Severity</td><td>{alert['severity']}</td></tr>
  <tr><td>Verdict</td><td>{alert['verdict']}</td></tr>
  <tr><td>Risk Score</td><td>{alert['risk_score']:.1f}/100</td></tr>
  <tr><td>Recommended Action</td><td>{alert['recommended_action']}</td></tr>
  <tr><td>Status</td><td>{alert['status']}</td></tr>
  <tr><td>Created At</td><td>{alert['created_at']}</td></tr>
</table>
<h3>Threat Summary</h3>
<div class="summary">{alert.get('threat_summary','No summary available.')}</div>
</body>
</html>"""
    return html.encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# ALERT STATS
# ══════════════════════════════════════════════════════════════════════════════

def get_alert_stats() -> dict:
    """Return counts by severity and status."""
    try:
        from backend.app.models import Alert
        rows  = Alert.query.all()
        stats = {
            "total":    len(rows),
            "open":     0,
            "acknowledged": 0,
            "dismissed":    0,
            "by_severity": {
                "Critical": 0, "High": 0,
                "Medium":   0, "Low":  0,
            },
            "by_module": {},
        }
        for r in rows:
            stats[r.status]                      = stats.get(r.status, 0) + 1
            stats["by_severity"][r.severity]     = (
                stats["by_severity"].get(r.severity, 0) + 1
            )
            stats["by_module"][r.module]         = (
                stats["by_module"].get(r.module, 0) + 1
            )
        return stats
    except Exception as ex:
        logger.error("get_alert_stats error: %s", ex)
        return {
            "total": 0, "open": 0,
            "acknowledged": 0, "dismissed": 0,
            "by_severity": {}, "by_module": {},
        }
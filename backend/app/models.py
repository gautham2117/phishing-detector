# models.py
# All SQLAlchemy ORM models for the application.
# Every class here maps to one database table.
# Add new models here as each phase is built.

from datetime import datetime
from backend.app.database import db


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Email Scanning
# ─────────────────────────────────────────────────────────────────────────────

class EmailScan(db.Model):
    """
    Stores one parsed email and its overall scan result.
    Parent record — URLScan, AttachmentScan, Alert, and NetworkScan
    all carry an optional email_scan_id foreign key back to this table.
    """
    __tablename__ = "email_scans"

    id           = db.Column(db.Integer, primary_key=True)
    filename     = db.Column(db.String(255))
    sender       = db.Column(db.String(255))
    recipient    = db.Column(db.String(255))
    subject      = db.Column(db.Text)
    body_text    = db.Column(db.Text)
    body_html    = db.Column(db.Text)
    headers_raw  = db.Column(db.Text)          # JSON string of all headers
    spf_result   = db.Column(db.String(50))    # pass / fail / softfail / none
    dkim_result  = db.Column(db.String(50))
    dmarc_result = db.Column(db.String(50))
    risk_score   = db.Column(db.Float, default=0.0)   # 0.0 – 100.0
    label        = db.Column(db.String(20))    # SAFE / SUSPICIOUS / MALICIOUS
    scanned_at   = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    urls         = db.relationship("URLScan",        backref="email", lazy=True)
    attachments  = db.relationship("AttachmentScan", backref="email", lazy=True)
    network_scans= db.relationship("NetworkScan",    backref="email", lazy=True)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — URL Intelligence
# ─────────────────────────────────────────────────────────────────────────────

class URLScan(db.Model):
    """
    Stores the full intelligence result for a single URL extracted
    from an email or submitted directly.
    """
    __tablename__ = "url_scans"

    id               = db.Column(db.Integer, primary_key=True)
    email_id         = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=True)

    raw_url          = db.Column(db.Text)
    normalized_url   = db.Column(db.Text)
    domain           = db.Column(db.String(255))
    ip_address       = db.Column(db.String(60))
    country          = db.Column(db.String(100))
    whois_data       = db.Column(db.Text)          # JSON string
    domain_age_days  = db.Column(db.Integer)
    ssl_valid        = db.Column(db.Boolean)
    ssl_issuer       = db.Column(db.String(255))
    redirect_chain   = db.Column(db.Text)          # JSON array of hop dicts
    ml_score         = db.Column(db.Float)         # 0.0 – 1.0 from BERT model
    rule_score       = db.Column(db.Float)         # score from rule engine
    final_label      = db.Column(db.String(20))    # BENIGN / SUSPICIOUS / MALICIOUS
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # One URL can trigger many network scans (one per scan type)
    network_scans    = db.relationship("NetworkScan", backref="url_scan", lazy=True)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Network Scanning
# ─────────────────────────────────────────────────────────────────────────────

class NetworkScan(db.Model):
    """
    One Nmap network scan against a single target domain or IP address.
    Contains many PortResult child rows — one per open port found.
    """
    __tablename__ = "network_scans"

    id               = db.Column(db.Integer, primary_key=True)

    # Optional back-links to parent scans
    url_scan_id      = db.Column(db.Integer, db.ForeignKey("url_scans.id"),   nullable=True)
    email_scan_id    = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=True)

    target           = db.Column(db.String(255))   # domain or IP that was scanned
    ip_resolved      = db.Column(db.String(60))    # IP the domain resolved to
    scan_type        = db.Column(db.String(50))    # quick / top100 / top1000 / full
    nmap_version     = db.Column(db.String(50))
    os_guess         = db.Column(db.String(255))   # OS fingerprint if available
    total_open_ports = db.Column(db.Integer, default=0)
    risk_level       = db.Column(db.String(20))    # LOW / MEDIUM / HIGH / CRITICAL
    risk_flags       = db.Column(db.Text)          # JSON list of flag strings
    raw_nmap_output  = db.Column(db.Text)          # truncated nmap result dict
    scan_duration_s  = db.Column(db.Float)
    authorized       = db.Column(db.Boolean, default=False)
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # One NetworkScan → many PortResults
    ports = db.relationship(
        "PortResult",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )


class PortResult(db.Model):
    """
    One row per open port discovered during a NetworkScan.
    """
    __tablename__ = "port_results"

    id               = db.Column(db.Integer, primary_key=True)
    network_scan_id  = db.Column(db.Integer, db.ForeignKey("network_scans.id"))

    port             = db.Column(db.Integer)
    protocol         = db.Column(db.String(10))    # tcp / udp
    state            = db.Column(db.String(20))    # open / filtered
    service_name     = db.Column(db.String(100))   # e.g. "http", "ssh"
    service_product  = db.Column(db.String(255))   # e.g. "Apache httpd"
    service_version  = db.Column(db.String(255))   # e.g. "2.4.41"
    service_extra    = db.Column(db.String(500))   # banner / extra info
    is_dangerous     = db.Column(db.Boolean, default=False)
    danger_reason    = db.Column(db.String(255))
    cpe              = db.Column(db.String(255))   # CPE software identifier


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — Attachment Analysis
# ─────────────────────────────────────────────────────────────────────────────

class AttachmentScan(db.Model):
    """
    Stores static analysis results for a file attachment extracted
    from an email. Phase 6 populates the full YARA and entropy fields.
    """
    __tablename__ = "attachment_scans"

    id            = db.Column(db.Integer, primary_key=True)
    email_id      = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=True)

    filename      = db.Column(db.String(255))
    file_type     = db.Column(db.String(50))       # pdf / docx / exe / zip ...
    md5           = db.Column(db.String(32))
    sha256        = db.Column(db.String(64))
    file_size     = db.Column(db.Integer)          # bytes
    entropy       = db.Column(db.Float)            # Shannon entropy (packed EXE signal)
    yara_matches  = db.Column(db.Text)             # JSON list of matched rule names
    static_finds  = db.Column(db.Text)             # JSON list of suspicious strings
    verdict       = db.Column(db.String(20))       # Clean / Suspicious / Malicious
    scanned_at    = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 13 — Alerting & Audit
# ─────────────────────────────────────────────────────────────────────────────

class Alert(db.Model):
    __tablename__ = "alerts"

    id                = db.Column(db.Integer,     primary_key=True)
    # Which module produced this alert
    module            = db.Column(db.String(50),  default="")
    input_type        = db.Column(db.String(30),  default="")
    # Reference to the source scan (generic — stores the scan table row id)
    scan_id           = db.Column(db.Integer,     nullable=True)
    # Core fields
    risk_score        = db.Column(db.Float,       default=0.0)
    severity          = db.Column(db.String(20),  default="Low")
    # Low | Medium | High | Critical
    verdict           = db.Column(db.String(30),  default="SUSPICIOUS")
    triggered_rules   = db.Column(db.Text,        default="[]")   # JSON list
    ml_verdicts       = db.Column(db.Text,        default="{}")   # JSON dict
    recommended_action= db.Column(db.String(30),  default="WARN")
    threat_summary    = db.Column(db.Text,        default="")     # BART output
    raw_findings      = db.Column(db.Text,        default="{}")   # JSON dict
    # Status
    status            = db.Column(db.String(20),  default="open")
    # open | acknowledged | dismissed
    acknowledged_by   = db.Column(db.String(100), default="")
    acknowledged_at   = db.Column(db.DateTime,    nullable=True)
    dismiss_reason    = db.Column(db.Text,        default="")
    # Timestamps
    created_at        = db.Column(db.DateTime,    default=datetime.utcnow)


class AuditLog(db.Model):
    """
    Immutable append-only audit trail.
    Never update or delete rows — only INSERT.
    """
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer,    primary_key=True)
    action     = db.Column(db.String(80), default="")
    # e.g. ALERT_CREATED, ALERT_ACKNOWLEDGED, ALERT_DISMISSED,
    #      SCAN_COMPLETED, FEEDBACK_LABELED, RETRAIN_TRIGGERED
    actor      = db.Column(db.String(100), default="system")
    module     = db.Column(db.String(50),  default="")
    object_id  = db.Column(db.Integer,    nullable=True)
    # ID of the alert / scan / feedback sample this action relates to
    detail     = db.Column(db.Text,       default="")  # JSON or plain text
    ip_address = db.Column(db.String(60), default="")
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)

# ─────────────────────────────────────────────────────────────────────────────
# Phase 12 — Continuous Learning
# ─────────────────────────────────────────────────────────────────────────────

class ModelVersion(db.Model):
    """
    Tracks every version of the retrained scikit-learn Random Forest model.
    Phase 12 writes new rows here after each retraining run and hot-swaps
    the active model without downtime.
    """
    __tablename__ = "model_versions"

    id               = db.Column(db.Integer,    primary_key=True)
    version_number   = db.Column(db.Integer,    default=1)
    model_type       = db.Column(db.String(50), default="rf_url_classifier")
    pkl_filename     = db.Column(db.String(255), default="")
    training_samples = db.Column(db.Integer,    default=0)
    feedback_samples = db.Column(db.Integer,    default=0)
    accuracy         = db.Column(db.Float,      nullable=True)
    precision        = db.Column(db.Float,      nullable=True)
    recall           = db.Column(db.Float,      nullable=True)
    f1_score         = db.Column(db.Float,      nullable=True)
    confusion_matrix = db.Column(db.Text,       default="[]")
    is_active        = db.Column(db.Boolean,    default=False)
    training_log     = db.Column(db.Text,       default="")
    created_at       = db.Column(db.DateTime,   default=datetime.utcnow)


class FeedbackSample(db.Model):
    """
    Labeled samples collected from analyst corrections.
    Used as the additional training dataset for model retraining in Phase 12.
    """
    __tablename__ = "feedback_samples"

    id                 = db.Column(db.Integer,    primary_key=True)
    url_scan_id        = db.Column(db.Integer,    nullable=True)
    url                = db.Column(db.String(2048), default="")
    original_label     = db.Column(db.String(30),  default="")
    feedback_label     = db.Column(db.String(30),  default="")
    label_type         = db.Column(db.String(30),  default="")
    admin_note         = db.Column(db.Text,         default="")
    used_in_training   = db.Column(db.Boolean,      default=False)
    created_at         = db.Column(db.DateTime,     default=datetime.utcnow)
    trained_in_version = db.Column(db.Integer,      nullable=True)
class AIDetectionScan(db.Model):
    __tablename__ = "ai_detection_scans"

    id             = db.Column(db.Integer,  primary_key=True)
    input_type     = db.Column(db.String(20),  default="text")   # text | url | file
    source_ref     = db.Column(db.String(512),  default="")      # URL or filename
    input_preview  = db.Column(db.Text,         default="")      # first 500 chars
    char_count     = db.Column(db.Integer,      default=0)
    sentence_count = db.Column(db.Integer,      default=0)
    ai_probability = db.Column(db.Float,        default=0.0)     # 0.0 – 1.0
    verdict        = db.Column(db.String(30),   default="HUMAN") # HUMAN | MIXED | AI_GENERATED
    risk_score     = db.Column(db.Float,        default=0.0)     # 0–100
    sentence_scores= db.Column(db.Text,         default="[]")    # JSON list
    scanned_at     = db.Column(db.DateTime,     default=datetime.utcnow)

class ImageAnalysisScan(db.Model):
    __tablename__ = "image_analysis_scans"

    id               = db.Column(db.Integer,  primary_key=True)
    filename         = db.Column(db.String(255), default="")
    file_size        = db.Column(db.Integer,     default=0)
    image_width      = db.Column(db.Integer,     default=0)
    image_height     = db.Column(db.Integer,     default=0)
    image_format     = db.Column(db.String(20),  default="")
    ocr_text         = db.Column(db.Text,        default="")
    ocr_word_count   = db.Column(db.Integer,     default=0)
    detected_brands  = db.Column(db.Text,        default="[]")   # JSON list
    phishing_keywords= db.Column(db.Text,        default="[]")   # JSON list
    classifier_label = db.Column(db.String(30),  default="")
    classifier_score = db.Column(db.Float,       default=0.0)
    verdict          = db.Column(db.String(30),  default="CLEAN")
    risk_score       = db.Column(db.Float,       default=0.0)
    scanned_at       = db.Column(db.DateTime,    default=datetime.utcnow)

class MonitoredTarget(db.Model):
    __tablename__ = "monitored_targets"

    id               = db.Column(db.Integer,     primary_key=True)
    url              = db.Column(db.String(2048), default="")
    domain           = db.Column(db.String(255),  default="")
    label            = db.Column(db.String(255),  default="")
    interval_minutes = db.Column(db.Integer,      default=60)
    alert_threshold  = db.Column(db.Float,        default=50.0)
    last_scanned     = db.Column(db.DateTime,     nullable=True)
    last_risk_score  = db.Column(db.Float,        default=0.0)
    last_verdict     = db.Column(db.String(30),   default="UNKNOWN")
    is_active        = db.Column(db.Boolean,      default=True)
    created_at       = db.Column(db.DateTime,     default=datetime.utcnow)
    scan_results     = db.relationship(
        "MonitorScanResult", backref="target",
        lazy=True, cascade="all, delete-orphan"
    )


class MonitorScanResult(db.Model):
    __tablename__ = "monitor_scan_results"

    id           = db.Column(db.Integer,  primary_key=True)
    target_id    = db.Column(db.Integer,  db.ForeignKey("monitored_targets.id"), nullable=False)
    risk_score   = db.Column(db.Float,    default=0.0)
    verdict      = db.Column(db.String(30), default="UNKNOWN")
    url_score    = db.Column(db.Float,    default=0.0)
    rules_score  = db.Column(db.Float,    default=0.0)
    ml_score     = db.Column(db.Float,    default=0.0)
    alert_fired  = db.Column(db.Boolean,  default=False)
    scan_summary = db.Column(db.Text,     default="")
    scanned_at   = db.Column(db.DateTime, default=datetime.utcnow)

class AggregatedRiskScore(db.Model):
    __tablename__ = "aggregated_risk_scores"

    id               = db.Column(db.Integer, primary_key=True)
    email_scan_id    = db.Column(db.Integer, nullable=True)
    url_scan_id      = db.Column(db.Integer, nullable=True)
    network_scan_id  = db.Column(db.Integer, nullable=True)
    attachment_id    = db.Column(db.Integer, nullable=True)
    ai_detection_id  = db.Column(db.Integer, nullable=True)
    image_scan_id    = db.Column(db.Integer, nullable=True)

    # Individual scores pulled from each table
    email_score      = db.Column(db.Float, nullable=True)
    url_score        = db.Column(db.Float, nullable=True)
    network_score    = db.Column(db.Float, nullable=True)
    attachment_score = db.Column(db.Float, nullable=True)
    ai_score         = db.Column(db.Float, nullable=True)
    image_score      = db.Column(db.Float, nullable=True)

    # Weights applied (stored so result is reproducible)
    email_weight     = db.Column(db.Float, default=0.20)
    url_weight       = db.Column(db.Float, default=0.25)
    network_weight   = db.Column(db.Float, default=0.15)
    attachment_weight= db.Column(db.Float, default=0.20)
    ai_weight        = db.Column(db.Float, default=0.10)
    image_weight     = db.Column(db.Float, default=0.10)

    final_score      = db.Column(db.Float,   default=0.0)
    verdict          = db.Column(db.String(30), default="UNKNOWN")
    phases_used      = db.Column(db.Text,    default="[]")  # JSON list
    breakdown        = db.Column(db.Text,    default="{}")  # JSON dict
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


class ExtensionScan(db.Model):
    __tablename__ = "extension_scans"

    id             = db.Column(db.Integer,    primary_key=True)
    url            = db.Column(db.String(2048), default="")
    domain         = db.Column(db.String(255),  default="")
    risk_score     = db.Column(db.Float,        default=0.0)
    label          = db.Column(db.String(30),   default="SAFE")
    verdict        = db.Column(db.String(30),   default="SAFE")
    threat_summary = db.Column(db.Text,         default="")
    recommended_action = db.Column(db.String(30), default="ALLOW")
    source         = db.Column(db.String(30),   default="extension")
    scanned_at     = db.Column(db.DateTime,     default=datetime.utcnow)
    
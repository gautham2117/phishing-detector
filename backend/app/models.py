# models.py
# All SQLAlchemy ORM models for the application.
# Each class maps to one database table.

from datetime import datetime
from .database import db


class EmailScan(db.Model):
    """Stores one parsed email and its overall scan result."""
    __tablename__ = "email_scans"

    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(255))          # original .eml filename
    sender      = db.Column(db.String(255))
    recipient   = db.Column(db.String(255))
    subject     = db.Column(db.Text)
    body_text   = db.Column(db.Text)                 # plain text body
    body_html   = db.Column(db.Text)                 # HTML body
    headers_raw = db.Column(db.Text)                 # raw header JSON string
    spf_result  = db.Column(db.String(50))           # pass / fail / none
    dkim_result = db.Column(db.String(50))
    dmarc_result= db.Column(db.String(50))
    risk_score  = db.Column(db.Float, default=0.0)   # 0–100
    label       = db.Column(db.String(20))           # SAFE / SUSPICIOUS / MALICIOUS
    scanned_at  = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships — one email has many URLs and attachments
    urls        = db.relationship("URLScan",        backref="email", lazy=True)
    attachments = db.relationship("AttachmentScan", backref="email", lazy=True)
    alerts      = db.relationship("Alert",          backref="email", lazy=True)


class URLScan(db.Model):
    """Stores analysis results for a single URL extracted from an email."""
    __tablename__ = "url_scans"

    id               = db.Column(db.Integer, primary_key=True)
    email_id         = db.Column(db.Integer, db.ForeignKey("email_scans.id"))
    raw_url          = db.Column(db.Text)
    normalized_url   = db.Column(db.Text)
    domain           = db.Column(db.String(255))
    ip_address       = db.Column(db.String(60))
    country          = db.Column(db.String(100))
    whois_data       = db.Column(db.Text)            # JSON string
    domain_age_days  = db.Column(db.Integer)
    ssl_valid        = db.Column(db.Boolean)
    ssl_issuer       = db.Column(db.String(255))
    redirect_chain   = db.Column(db.Text)            # JSON array of hops
    ml_score         = db.Column(db.Float)           # ML classifier output
    rule_score       = db.Column(db.Float)           # rule engine output
    final_label      = db.Column(db.String(20))
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)


class AttachmentScan(db.Model):
    """Stores analysis results for a file attachment."""
    __tablename__ = "attachment_scans"

    id            = db.Column(db.Integer, primary_key=True)
    email_id      = db.Column(db.Integer, db.ForeignKey("email_scans.id"))
    filename      = db.Column(db.String(255))
    file_type     = db.Column(db.String(50))         # pdf, docx, exe, etc.
    md5           = db.Column(db.String(32))
    sha256        = db.Column(db.String(64))
    file_size     = db.Column(db.Integer)            # bytes
    entropy       = db.Column(db.Float)              # Shannon entropy
    yara_matches  = db.Column(db.Text)               # JSON array of rule names
    static_finds  = db.Column(db.Text)               # JSON array of strings found
    verdict       = db.Column(db.String(20))         # Clean / Suspicious / Malicious
    scanned_at    = db.Column(db.DateTime, default=datetime.utcnow)


class Alert(db.Model):
    """One alert generated per suspicious/malicious scan."""
    __tablename__ = "alerts"

    id               = db.Column(db.Integer, primary_key=True)
    email_id         = db.Column(db.Integer, db.ForeignKey("email_scans.id"), nullable=True)
    input_type       = db.Column(db.String(20))      # Email / URL / SMS / File / Image
    risk_score       = db.Column(db.Float)
    severity         = db.Column(db.String(20))      # Low / Medium / High / Critical
    triggered_rules  = db.Column(db.Text)            # JSON list
    ml_verdicts      = db.Column(db.Text)            # JSON dict: {model: result}
    bart_summary     = db.Column(db.Text)            # AI-generated plain-language explanation
    recommended_action = db.Column(db.String(20))    # ALLOW / WARN / QUARANTINE / BLOCK
    is_false_positive  = db.Column(db.Boolean, default=False)
    analyst_label    = db.Column(db.String(20))      # human override label
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)


class ModelVersion(db.Model):
    """Tracks versions of the retrained scikit-learn Random Forest model."""
    __tablename__ = "model_versions"

    id         = db.Column(db.Integer, primary_key=True)
    version    = db.Column(db.String(20))            # e.g., "v1.0", "v1.1"
    model_path = db.Column(db.String(255))           # path to .pkl file
    accuracy   = db.Column(db.Float)
    precision  = db.Column(db.Float)
    recall     = db.Column(db.Float)
    f1_score   = db.Column(db.Float)
    is_active  = db.Column(db.Boolean, default=False)
    trained_at = db.Column(db.DateTime, default=datetime.utcnow)


class FeedbackSample(db.Model):
    """Labeled samples collected from analyst corrections for retraining."""
    __tablename__ = "feedback_samples"

    id           = db.Column(db.Integer, primary_key=True)
    input_type   = db.Column(db.String(20))
    raw_input    = db.Column(db.Text)                # URL or email body
    true_label   = db.Column(db.String(20))          # correct label from analyst
    predicted    = db.Column(db.String(20))          # what the model said
    labeled_by   = db.Column(db.String(100))         # analyst username
    labeled_at   = db.Column(db.DateTime, default=datetime.utcnow)
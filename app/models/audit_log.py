import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from ..extensions import db

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Who performed the action (nullable for anonymous/system)
    actor_user_id = db.Column(UUID(as_uuid=True), nullable=True, index=True)
    actor_role = db.Column(db.String(30), nullable=True)

    # What happened
    action = db.Column(db.String(80), nullable=False, index=True)  # e.g. POLL_CREATED
    entity_type = db.Column(db.String(50), nullable=True, index=True)  # e.g. POLL, VOTE, AUTH
    entity_id = db.Column(UUID(as_uuid=True), nullable=True, index=True)

    # Request context
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    # Extra structured details (safe to store JSON)
    details = db.Column(JSONB, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

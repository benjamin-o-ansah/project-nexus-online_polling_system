import uuid
from datetime import datetime, timedelta
from sqlalchemy.dialects.postgresql import UUID
from ..extensions import db

class OTPChallenge(db.Model):
    __tablename__ = "otp_challenges"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), nullable=False, index=True)

    otp_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_sent_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at

    def is_used(self) -> bool:
        return self.used_at is not None

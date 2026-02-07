import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from ..extensions import db

class Option(db.Model):
    __tablename__ = "poll_options"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    poll_id = db.Column(UUID(as_uuid=True), db.ForeignKey("polls.id", ondelete="CASCADE"), nullable=False, index=True)

    text = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.Index("ix_poll_options_poll_id", "poll_id"),
    )

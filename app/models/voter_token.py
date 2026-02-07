import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from ..extensions import db

class VoterToken(db.Model):
    __tablename__ = "voter_tokens"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    poll_id = db.Column(UUID(as_uuid=True), db.ForeignKey("polls.id", ondelete="CASCADE"), nullable=False, index=True)

    # Store only a hash of the token for security
    token_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.Index("ix_voter_tokens_poll_id", "poll_id"),
    )

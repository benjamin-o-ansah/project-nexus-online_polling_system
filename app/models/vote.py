import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from ..extensions import db

class Vote(db.Model):
    __tablename__ = "votes"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    poll_id = db.Column(UUID(as_uuid=True), db.ForeignKey("polls.id", ondelete="CASCADE"), nullable=False, index=True)
    option_id = db.Column(UUID(as_uuid=True), db.ForeignKey("poll_options.id", ondelete="CASCADE"), nullable=False, index=True)

    # Authenticated voter (optional)
    user_id = db.Column(UUID(as_uuid=True), nullable=True, index=True)

    # Anonymous voter token (optional)
    anon_token_hash = db.Column(db.String(255), nullable=True, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        # One vote per user per poll (when user_id is present)
        db.UniqueConstraint("poll_id", "user_id", name="uq_votes_poll_user"),
        # One vote per anonymous token per poll (when anon_token_hash is present)
        db.UniqueConstraint("poll_id", "anon_token_hash", name="uq_votes_poll_anon"),
        db.Index("ix_votes_poll_id", "poll_id"),
        db.Index("ix_votes_option_id", "option_id"),
    )

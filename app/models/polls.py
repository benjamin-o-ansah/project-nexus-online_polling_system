import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from ..extensions import db

class Poll(db.Model):
    __tablename__ = "polls"

    STATUS_DRAFT = "DRAFT"
    STATUS_ACTIVE = "ACTIVE"
    STATUS_CLOSED = "CLOSED"
    VALID_STATUSES = (STATUS_DRAFT, STATUS_ACTIVE, STATUS_CLOSED)

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    owner_id = db.Column(UUID(as_uuid=True), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(20), nullable=False, default=STATUS_DRAFT)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)

    # relationship
    options = db.relationship(
        "Option",
        backref="poll",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def can_edit(self) -> bool:
        return self.status == self.STATUS_DRAFT

    def publish(self):
        if self.status != self.STATUS_DRAFT:
            raise ValueError("Only draft polls can be published")
        self.status = self.STATUS_ACTIVE
        self.published_at = datetime.utcnow()

    def close(self):
        if self.status != self.STATUS_ACTIVE:
            raise ValueError("Only active polls can be closed")
        self.status = self.STATUS_CLOSED
        self.closed_at = datetime.utcnow()

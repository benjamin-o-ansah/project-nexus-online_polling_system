from datetime import datetime
from ..extensions import db

class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @staticmethod
    def is_blocklisted(jti: str) -> bool:
        return db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar() is not None

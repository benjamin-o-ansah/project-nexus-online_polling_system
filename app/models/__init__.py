from .user import User  # noqa: F401
from .otp_challenge import OTPChallenge  # noqa: F401
from .token_blocklist import TokenBlocklist  # noqa: F401
from .polls import Poll  # noqa: F401
from .option import Option  # noqa: F401
from .vote import Vote  # noqa: F401
from .voter_token import VoterToken
from .audit_log import AuditLog  # noqa: F401
from app.extensions import db

# Import ALL models so SQLAlchemy registers them

__all__ = [
    "User",
    "Poll",
    "Option",
    "Vote",
    "AuditLog",
    "OTPChallenge",
    "TokenBlocklist",
]


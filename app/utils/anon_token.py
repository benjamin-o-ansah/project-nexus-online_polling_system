import secrets
import hmac
import hashlib
from flask import current_app

def generate_raw_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def token_digest(raw_token: str) -> str:
    """
    Deterministic digest using HMAC-SHA256 with SECRET_KEY.
    Safe to store in DB; raw token stays client-side.
    """
    secret = current_app.config["SECRET_KEY"].encode("utf-8")
    msg = raw_token.encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

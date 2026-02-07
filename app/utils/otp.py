import secrets
import string
from werkzeug.security import generate_password_hash, check_password_hash

def generate_otp(length: int = 6) -> str:
    digits = string.digits
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp(otp: str) -> str:
    return generate_password_hash(otp)

def verify_otp(otp: str, otp_hash: str) -> bool:
    return check_password_hash(otp_hash, otp)

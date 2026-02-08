import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent  # project root (where wsgi.py is)
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-dev-secret")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_MIN", "30"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "7"))
    )

    # # OTP
    # OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
    # OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))  # 5 minutes
    # OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
    # OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))

    # # Mail (SMTP)
    # BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    # BREVO_SENDER_EMAIL = os.environ.get('BREVO_SENDER_EMAIL', 'memphisperla@gmail.com')
    # BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'Project Nexus Online Polling System')
    
    # # Keep your OTP config
    # OTP_LENGTH = int(os.environ.get('OTP_LENGTH', 6))
    # OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', 300))
    # OTP_MAX_ATTEMPTS = int(os.environ.get('OTP_MAX_ATTEMPTS', 3))
    # SWAGGER = {"title": "Online Polling System API", "uiversion": 3}
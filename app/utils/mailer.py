from flask_mail import Message
from flask import current_app
from ..extensions import mail

def send_otp_email(to_email: str, otp: str) -> None:
    sender = current_app.config.get("MAIL_DEFAULT_SENDER")
    if not sender:
        # Fail fast with a meaningful message (instead of Flask-Mail assertion)
        raise RuntimeError(
            "MAIL_DEFAULT_SENDER is not configured. Set MAIL_DEFAULT_SENDER in .env"
        )

    subject = "Your Login OTP Code"
    body = (
        f"Your OTP code is: {otp}\n\n"
        f"It expires in {current_app.config['OTP_TTL_SECONDS'] // 60} minutes.\n"
        "If you did not request this code, please ignore this email."
    )
    msg = Message(subject=subject, recipients=[to_email], body=body, sender=sender)
    mail.send(msg)

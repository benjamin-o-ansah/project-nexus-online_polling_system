from flask import Blueprint, request, current_app
from flasgger import swag_from
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,get_jwt
)
from datetime import datetime, timedelta
# from sqlalchemy.exc import IntegrityError
from ...utils.audit import audit_log,secure_audit_log
from ...extensions import db
from ...models.user import User
# from ...models.otp_challenge import OTPChallenge
from ...models.token_blocklist import TokenBlocklist
from ...schemas.auth import RegisterSchema, LoginSchema
from ...schemas.user import UserSchema

from ...utils.validation import validate_or_abort
from datetime import datetime


from app.schemas import user

from app.utils import otp

auth_bp = Blueprint("auth", __name__)

register_schema = RegisterSchema()
login_req_schema= LoginSchema()
user_schema = UserSchema()


@auth_bp.post("/register")
@swag_from({
    "tags": ["Auth"],
    "summary": "Register a user",
    "description": "Registers a new user (Poll Admin or Voter).",
    "parameters": [{
        "in": "body",
        "name": "body",
        "required": True,
        "schema": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "example": "admin@example.com"},
                "password": {"type": "string", "example": "StrongPass123"},
                "role": {"type": "string", "example": "POLL_ADMIN"}
            },
            "required": ["email", "password"]
        }
    }],
    "responses": {
        "201": {"description": "User created"},
        "400": {"description": "Validation error"},
        "409": {"description": "Email already exists"}
    }
})
def register():
   
    payload = validate_or_abort(register_schema, request.get_json(silent=True) or {})
    email = payload["email"].lower().strip()

    if User.query.filter_by(email=email).first():
        secure_audit_log(
            action="REGISTER_FAILED_EMAIL_EXISTS",
            entity_type="AUTH",
            details={"email": email}
        )
        return {"message": "Email already registered"}, 409

    user = User(email=email, role=payload.get("role", "VOTER"))
    user.set_password(payload["password"])

    with db.session.begin():
        db.session.add(user)
        audit_log(
            "USER_REGISTERED",
            "AUTH",
            details={"email": user.email, "role": user.role}
        )

    return {"message": "User registered successfully", "user": user_schema.dump(user)}, 201


@auth_bp.post("/login")
@swag_from({
    "tags": ["Auth"],
    "summary": "Login with email and password",
    "description": "Validates email/password and returns access/refresh tokens on successful login.",
    "responses": {
        200: {"description": "Login successful, tokens returned"},
        400: {"description": "Validation error"},
        401: {"description": "Invalid credentials"},
        403: {"description": "User account not active"}
    }
})
def login():
    """
    Authenticate user with email and password
    Returns access and refresh tokens on successful authentication
    """
    payload = validate_or_abort(login_req_schema, request.get_json(silent=True) or {})
   
    email = payload["email"].lower().strip()
    password = payload["password"]

    user = User.query.filter_by(email=email).first()

    # --- SECURITY EVENTS (persist independently)
    if not user or not user.check_password(password):
        secure_audit_log(
            "LOGIN_FAILED_INVALID_CREDENTIALS",
            "AUTH",
            details={"email": email}
        )
        return {"message": "Invalid email or password"}, 401

    if not user.is_active:
        secure_audit_log(
            "LOGIN_FAILED_INACTIVE_ACCOUNT",
            "AUTH",
            details={"email": user.email, "user_id": str(user.id)}
        )
        return {"message": "Account is inactive"}, 403

    # --- Business Transaction (atomic)
    try:
        access = create_access_token(identity=str(user.id), additional_claims={"role": user.role})
        refresh = create_refresh_token(identity=str(user.id), additional_claims={"role": user.role})

        with db.session.begin():
            if hasattr(user, "last_login_at"):
                user.last_login_at = datetime.utcnow()

            audit_log(
                "LOGIN_SUCCESS",
                "AUTH",
                details={"user_id": str(user.id), "email": user.email, "role": user.role}
            )

        return {
            "message": "Login successful",
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "user": user_schema.dump(user)
        }, 200

    except Exception as e:
        secure_audit_log(
            "LOGIN_TOKEN_GENERATION_FAILED",
            "AUTH",
            details={"error": str(e), "user_id": str(user.id)}
        )
        return {"message": "Authentication error"}, 500





# @auth_bp.post("/login/request-otp")
# @swag_from({
#     "tags": ["Auth"],
#     "summary": "Request OTP for login",
#     "description": "Validates email/password, then sends OTP. Returns a challenge_id used to verify OTP and complete login.",
#     "responses": {200: {"description": "OTP sent"}, 400: {"description": "Validation error"}, 401: {"description": "Invalid credentials"}}
# })
# def request_login_otp():
#     payload = request.get_json(silent=True) or {}
#     payload = validate_or_abort(login_req_schema, payload)
#     email = payload["email"].lower().strip()
#     password = payload["password"]

#     user = User.query.filter_by(email=email).first()
#     if not user or not user.is_active or not user.check_password(password):
#         audit_log(
#             action="LOGIN_OTP_REQUEST_DENIED",
#             entity_type="AUTH",
#             details={"email": email}
#         )
#         return {"message": "Invalid credentials"}, 401

#     # Generate OTP + store hashed
#     otp = generate_otp(current_app.config["OTP_LENGTH"])
#     ttl = current_app.config["OTP_TTL_SECONDS"]
#     challenge = OTPChallenge(
#         user_id=user.id,
#         otp_hash=hash_otp(otp),
#         expires_at=datetime.utcnow() + timedelta(seconds=ttl),
#         last_sent_at=datetime.utcnow(),
#         attempts=0,
#     )
#     db.session.add(challenge)
#     db.session.flush()
    
#     audit_log(
#         action="LOGIN_OTP_REQUESTED",
#         entity_type="AUTH",
#         details={
#             "email": user.email,
#             "challenge_id": str(challenge.id)
#         }
#     )
#     db.session.commit()

#     # Send OTP via Brevo
#     try:
#         send_login_otp_email(user.email, otp)
#         audit_log(action="LOGIN_OTP_EMAIL_SENT", entity_type="AUTH", details={"email": user.email})
#     except Exception as e:
#         current_app.logger.warning("OTP email failed: %s", str(e))
#         audit_log(
#             action="LOGIN_OTP_EMAIL_FAILED",
#             entity_type="AUTH",
#             details={"email": user.email, "reason": str(e)},
#         )

#     # Always return success-ish response to avoid leaking whether user exists
#         return {"success": True, "message": "If the email is valid, an OTP will be delivered shortly."}, 202
        



# @auth_bp.post("/login/verify-otp")
# @swag_from({
#     "tags": ["Auth"],
#     "summary": "Verify OTP and login",
#     "description": "Verifies OTP challenge; on success returns access/refresh tokens and a message that login was successful.",
#     "responses": {200: {"description": "Tokens issued"}, 400: {"description": "Validation error"}, 401: {"description": "Invalid/expired OTP"}}
# })
# def verify_login_otp():
#     payload = request.get_json(silent=True) or {}
#     payload = validate_or_abort(login_verify_schema, payload)
#     challenge_id = payload["challenge_id"]
#     otp = payload["otp"].strip()

#     challenge = OTPChallenge.query.get(challenge_id)
#     if not challenge:
#         audit_log(
#     action="LOGIN_OTP_VERIFY_FAILED",
#     entity_type="AUTH",
#     details={
#         "challenge_id": str(challenge.id),
#         "attempts": challenge.attempts
#     }
# )

#         return {"message": "Invalid OTP"}, 401

#     if challenge.is_used() or challenge.is_expired():
#         audit_log(
#     action="LOGIN_OTP_EXPIRED",
#     entity_type="AUTH",
#     details={"challenge_id": str(challenge.id)}
# )

#         return {"message": "OTP expired or already used"}, 401

#     max_attempts = current_app.config["OTP_MAX_ATTEMPTS"]
#     if challenge.attempts >= max_attempts:
#         audit_log(
#     action="LOGIN_OTP_ATTEMPTS_EXCEEDED",
#     entity_type="AUTH",
#     details={
#         "challenge_id": str(challenge.id),
#         "attempts": challenge.attempts
#     }
# )

#         return {"message": "OTP attempts exceeded"}, 401

#     # Increment attempts before verification to prevent timing attacks
#     challenge.attempts += 1
#     db.session.flush()

#     if not verify_otp(otp, challenge.otp_hash):
#         db.session.commit()
#         return {"message": "Invalid OTP"}, 401

#     # Mark used
#     challenge.used_at = datetime.utcnow()

#     user = User.query.get(challenge.user_id)
#     if not user or not user.is_active:
#         db.session.commit()
#         return {"message": "User inactive or not found"}, 401

#     additional_claims = {"role": user.role}
#     access = create_access_token(identity=str(user.id), additional_claims=additional_claims)
#     refresh = create_refresh_token(identity=str(user.id), additional_claims=additional_claims)

#     db.session.commit()
#     audit_log(
#     action="LOGIN_SUCCESS",
#     entity_type="AUTH",
#     details={
#         "user_id": str(user.id),
#         "role": user.role
#     }
# )


#     return {"access_token": access, "refresh_token": refresh, "message": "Login successful"}, 200


# ---------- TOKEN REFRESH / ME / LOGOUT ----------

@auth_bp.post("/refresh")
@jwt_required(refresh=True)
@swag_from({
  "tags": ["Auth"],
  "security": [{"BearerAuth": []}],
  "summary": "Refresh access token (requires refresh token)",
  "responses": {
    200: {"description": "New access token issued"},
    401: {"description": "Unauthorized", "schema": {"$ref": "#/definitions/ErrorResponse"}},
    422: {"description": "Invalid token", "schema": {"$ref": "#/definitions/ErrorResponse"}}
  }
})
def refresh():
    
  user_id = get_jwt_identity()
  user = User.query.get(user_id)

  if not user or not user.is_active:
    return {"message": "User inactive or not found"}, 401

  access = create_access_token(identity=str(user.id), additional_claims={"role": user.role})

  with db.session.begin():
        audit_log(
            "TOKEN_REFRESHED",
            "AUTH",
            details={"user_id": str(user.id)}
        )

  return {"access_token": access}, 200



@auth_bp.get("/me")
@jwt_required()
@swag_from({
  "tags": ["Auth"],
  "security": [{"BearerAuth": []}],
  "summary": "Get current user profile",
  "responses": {
    200: {"description": "User profile"},
    401: {"description": "Unauthorized", "schema": {"$ref": "#/definitions/ErrorResponse"}},
    404: {"description": "User not found", "schema": {"$ref": "#/definitions/ErrorResponse"}}
  }
})
def me():
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return {"message": "User not found"}, 404

    # READ event → secure audit (no DB mutation)
    secure_audit_log(
        "AUTH_ME_VIEWED",
        "AUTH",
        details={"user_id": str(user.id)}
    )

    return {"user": user_schema.dump(user)}, 200



@auth_bp.post("/logout")
@jwt_required()
@swag_from({
  "tags": ["Auth"],
  "security": [{"BearerAuth": []}],
  "summary": "Logout (revoke access token)",
  "responses": {
    200: {"description": "Logged out"},
    401: {"description": "Unauthorized", "schema": {"$ref": "#/definitions/ErrorResponse"}},
    422: {"description": "Invalid token", "schema": {"$ref": "#/definitions/ErrorResponse"}}
  }
})
def logout():
    """
    Logout by revoking the current access token (blocklisting its jti).
    For full logout, client should also revoke refresh token by calling /logout with refresh token.
    """
    jwt_payload = get_jwt()
    jti = jwt_payload.get("jti")
    user_id = get_jwt_identity()

    with db.session.begin():
        db.session.add(TokenBlocklist(jti=jti))
        audit_log(
            "LOGOUT_ACCESS",
            "AUTH",
            details={"user_id": str(user_id), "jti": jti}
        )
    return {"message": "Logged out successfully"}, 200



@auth_bp.post("/logout/refresh")
@jwt_required(refresh=True)
def logout_refresh():
    """Revoke the refresh token to fully log out the session."""
    
    jwt_payload = get_jwt()
    jti = jwt_payload.get("jti")
    user_id = get_jwt_identity()

    with db.session.begin():
        db.session.add(TokenBlocklist(jti=jti))
        audit_log(
            "LOGOUT_REFRESH",
            "AUTH",
            details={"user_id": str(user_id), "jti": jti}
        )
    return {"message": "Refresh token revoked"}, 200



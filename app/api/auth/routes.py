from flask import Blueprint, request, current_app
from flasgger import swag_from
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
    get_jwt,
)
from datetime import datetime
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ...utils.audit import audit_log
from ...extensions import db
from ...models.user import User
from ...models.token_blocklist import TokenBlocklist
from ...schemas.auth import RegisterSchema, LoginSchema
from ...schemas.user import UserSchema
from ...utils.validation import validate_or_abort

auth_bp = Blueprint("auth", __name__)

register_schema = RegisterSchema()
login_req_schema = LoginSchema()
user_schema = UserSchema()


def _safe_audit_read(action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None):
    """
    Best-effort audit for read-only endpoints.
    Does not break the endpoint if auditing fails.
    """
    try:
        audit_log(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details or {},
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Audit logging failed (read endpoint): %s", action)


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
    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(register_schema, payload)

    email = payload["email"].lower().strip()
    password = payload["password"]
    role = payload.get("role", "VOTER")

    if User.query.filter_by(email=email).first():
        # Optional: audit registration attempt (no user created)
        _safe_audit_read(
            action="USER_REGISTER_FAILED_EMAIL_EXISTS",
            entity_type="AUTH",
            details={"email": email, "role": role},
        )
        return {"message": "Email already registered"}, 409

    user = User(email=email, role=role)
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.flush()  # ensure user.id exists for audit if needed

        audit_log(
            action="USER_REGISTERED",
            entity_type="AUTH",
            entity_id=str(user.id),
            details={"email": user.email, "role": user.role},
        )

        db.session.commit()
        return {"message": "User registered successfully", "user": user_schema.dump(user)}, 201

    except IntegrityError:
        db.session.rollback()
        return {"message": "Failed to register user"}, 500
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error during register")
        return {"message": "Failed to register user"}, 500


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
    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(login_req_schema, payload)

    email = payload["email"].lower().strip()
    password = payload["password"]

    try:
        user = User.query.filter_by(email=email).first()

        # Invalid credentials (don't leak which part failed)
        if not user or not user.check_password(password):
            audit_log(
                action="LOGIN_FAILED_INVALID_CREDENTIALS",
                entity_type="AUTH",
                details={"email": email},
            )
            db.session.commit()
            return {"message": "Invalid email or password"}, 401

        # Inactive account
        if not user.is_active:
            audit_log(
                action="LOGIN_FAILED_INACTIVE_ACCOUNT",
                entity_type="AUTH",
                entity_id=str(user.id),
                details={"user_id": str(user.id), "email": user.email},
            )
            db.session.commit()
            return {"message": "Account is not active. Please contact support."}, 403

        # Generate tokens (no DB write)
        additional_claims = {"role": user.role}
        access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=str(user.id), additional_claims=additional_claims)

        # Optional DB update: last_login_at
        if hasattr(user, "last_login_at"):
            user.last_login_at = datetime.utcnow()

        # Audit success (DB write)
        audit_log(
            action="LOGIN_SUCCESS",
            entity_type="AUTH",
            entity_id=str(user.id),
            details={"user_id": str(user.id), "email": user.email, "role": user.role},
        )

        # ✅ Single commit persists last_login_at (if changed) + audit row
        db.session.commit()

        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "role": user.role,
            },
        }, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error during login")
        # Best-effort audit for system failure
        _safe_audit_read(
            action="LOGIN_DB_ERROR",
            entity_type="AUTH",
            details={"email": email},
        )
        return {"message": "Authentication service error. Please try again."}, 500
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Unexpected error during login")
        # Best-effort audit for unexpected failure
        _safe_audit_read(
            action="LOGIN_TOKEN_GENERATION_FAILED",
            entity_type="AUTH",
            details={"email": email, "error": str(e)},
        )
        return {"message": "Authentication service error. Please try again."}, 500


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
@swag_from({
    "tags": ["Auth"],
    "security": [{"BearerAuth": []}],
    "summary": "Refresh access token (requires refresh token)",
    "responses": {
        200: {"description": "New access token issued"},
        401: {"description": "Unauthorized"},
        422: {"description": "Invalid token"},
    },
})
def refresh():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.is_active:
        return {"message": "User inactive or not found"}, 401

    try:
        access = create_access_token(identity=str(user.id), additional_claims={"role": user.role})

        audit_log(
            action="TOKEN_REFRESHED",
            entity_type="AUTH",
            entity_id=str(user.id),
            details={"user_id": str(user.id)},
        )

        db.session.commit()
        return {"access_token": access}, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error during refresh")
        return {"message": "Token refresh failed"}, 500


@auth_bp.get("/me")
@jwt_required()
@swag_from({
    "tags": ["Auth"],
    "security": [{"BearerAuth": []}],
    "summary": "Get current user profile",
    "responses": {
        200: {"description": "User profile"},
        401: {"description": "Unauthorized"},
        404: {"description": "User not found"},
    },
})
def me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return {"message": "User not found"}, 404

    # Read endpoint: best-effort audit (don't break profile fetch if auditing fails)
    _safe_audit_read(
        action="AUTH_ME_VIEWED",
        entity_type="AUTH",
        entity_id=str(user.id),
        details={"user_id": str(user.id)},
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
        401: {"description": "Unauthorized"},
        422: {"description": "Invalid token"},
    },
})
def logout():
    jwt_payload = get_jwt()
    jti = jwt_payload.get("jti")
    if not jti:
        return {"message": "Invalid token"}, 400

    try:
        db.session.add(TokenBlocklist(jti=jti))

        audit_log(
            action="LOGOUT_ACCESS",
            entity_type="AUTH",
            details={"user_id": str(get_jwt_identity()), "jti": jti},
        )

        db.session.commit()
        return {"message": "Logged out successfully"}, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error during logout")
        return {"message": "Logout failed"}, 500


@auth_bp.post("/logout/refresh")
@jwt_required(refresh=True)
def logout_refresh():
    jwt_payload = get_jwt()
    jti = jwt_payload.get("jti")
    if not jti:
        return {"message": "Invalid token"}, 400

    try:
        db.session.add(TokenBlocklist(jti=jti))

        audit_log(
            action="LOGOUT_REFRESH",
            entity_type="AUTH",
            details={"user_id": str(get_jwt_identity()), "jti": jti},
        )

        db.session.commit()
        return {"message": "Refresh token revoked"}, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error during refresh logout")
        return {"message": "Logout failed"}, 500

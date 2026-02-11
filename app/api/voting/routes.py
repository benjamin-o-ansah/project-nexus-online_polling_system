
from flask import Blueprint, request, current_app
from flasgger import swag_from
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request, get_jwt

from ...utils.audit import audit_log
from ...utils.validation import validate_or_abort
from ...extensions import db
from ...models.polls import Poll
from ...models.option import Option
from ...models.vote import Vote
from ...models.voter_token import VoterToken
from ...schemas.vote import VoteSubmitSchema
from ...utils.anon_token import generate_raw_token, token_digest

voting_bp = Blueprint("voting", __name__)
vote_submit_schema = VoteSubmitSchema()

ALLOWED_AUTH_VOTER_ROLES = {"VOTER", "POLL_ADMIN", "SYSTEM_ADMIN"}


def _get_optional_jwt_identity():
    """
    Allow both authenticated and anonymous requests.
    Returns (user_id, role) or (None, None).
    """
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt() or {}
        return get_jwt_identity(), claims.get("role")
    except Exception as e:
        current_app.logger.debug("Optional JWT check failed: %s", e)
        return None, None


def _safe_audit_read(action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None):
    """
    Best-effort audit for read-only endpoints.
    IMPORTANT: should not break endpoint even if audit fails.
    """
    try:
        audit_log(action=action, entity_type=entity_type, entity_id=entity_id, details=details or {})
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Audit logging failed (read endpoint): %s", action)


def _get_anon_secret_or_raise() -> str:
    secret = current_app.config.get("ANON_TOKEN_SECRET")
    if not secret:
        raise KeyError("ANON_TOKEN_SECRET")
    return secret


@voting_bp.post("/<uuid:poll_id>/vote")
@swag_from({
    "tags": ["Voting"],
    "summary": "Submit a vote (authenticated or anonymous). Auth roles allowed: VOTER, POLL_ADMIN, SYSTEM_ADMIN",
    "responses": {
        201: {"description": "Vote recorded"},
        400: {"description": "Validation error"},
        403: {"description": "Forbidden"},
        404: {"description": "Poll/Option not found"},
        409: {"description": "Duplicate vote"},
        500: {"description": "Server error"},
    },
})
def submit_vote(poll_id):
    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(vote_submit_schema, payload)

    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    if poll.status != Poll.STATUS_ACTIVE:
        _safe_audit_read(
            action="VOTE_SUBMIT_DENIED",
            entity_type="VOTE",
            details={"poll_id": str(poll_id), "reason": "poll_not_active", "status": poll.status},
        )
        return {"message": "Voting is not allowed on this poll"}, 403

    option_id = payload["option_id"]  # marshmallow UUID -> uuid.UUID
    option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
    if not option:
        return {"message": "Option not found for this poll"}, 404

    user_id, role = _get_optional_jwt_identity()

    # Authenticated role gate (SYSTEM_ADMIN allowed)
    if user_id and role not in ALLOWED_AUTH_VOTER_ROLES:
        _safe_audit_read(
            action="VOTE_SUBMIT_DENIED",
            entity_type="VOTE",
            details={
                "poll_id": str(poll_id),
                "option_id": str(option.id),
                "reason": "role_not_allowed",
                "role": role,
                "user_id": str(user_id),
            },
        )
        return {"message": "You are not allowed to vote"}, 403

    raw_token = payload.get("voter_token")
    issued_token = None
    vote = None

    try:
        # ---- Build vote row (no session.begin block) ----
        if user_id:
            vote = Vote(poll_id=poll_id, option_id=option.id, user_id=user_id, anon_token_hash=None)
            db.session.add(vote)
            db.session.flush()  # ensure vote.id for audit
            audit_log(
                action="VOTE_SUBMITTED",
                entity_type="VOTE",
                entity_id=str(vote.id),
                details={
                    "poll_id": str(poll_id),
                    "option_id": str(option.id),
                    "user_id": str(user_id),
                    "mode": "authenticated",
                    "role": role,
                },
            )
        else:
            secret = _get_anon_secret_or_raise()

            if not raw_token:
                issued_token = generate_raw_token()
                anon_token_hash = token_digest(issued_token, secret)
                db.session.add(VoterToken(poll_id=poll_id, token_hash=anon_token_hash))
            else:
                anon_token_hash = token_digest(raw_token, secret)

            vote = Vote(poll_id=poll_id, option_id=option.id, user_id=None, anon_token_hash=anon_token_hash)
            db.session.add(vote)
            db.session.flush()

            audit_log(
                action="VOTE_SUBMITTED",
                entity_type="VOTE",
                entity_id=str(vote.id),
                details={
                    "poll_id": str(poll_id),
                    "option_id": str(option.id),
                    "user_id": None,
                    "mode": "anonymous",
                    "token_issued": bool(issued_token),
                },
            )

        # ✅ single commit for vote + (optional token) + audit
        db.session.commit()

        response = {
            "message": "Vote recorded",
            "vote_id": str(vote.id),
            "poll_id": str(poll_id),
            "option_id": str(option.id),
        }
        if issued_token:
            response["voter_token"] = issued_token
        return response, 201

    except IntegrityError as e:
        db.session.rollback()
        current_app.logger.info("Vote constraint/duplicate error: %s", str(e), exc_info=True)
        return {"message": "You have already voted in this poll"}, 409

    except KeyError:
        db.session.rollback()
        current_app.logger.exception("Voting configuration error (missing ANON_TOKEN_SECRET)")
        return {"message": "Voting service misconfigured"}, 500

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.exception("DB error while submitting vote: %s", str(e))
        return {"message": "Failed to record vote"}, 500

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Unexpected error while submitting vote: %s", str(e))
        return {"message": "Failed to record vote"}, 500


@voting_bp.get("/<uuid:poll_id>/vote/status")
@swag_from({
    "tags": ["Voting"],
    "summary": "Check vote status for current user or anonymous token",
    "parameters": [{"in": "query", "name": "voter_token", "required": False, "type": "string"}],
    "responses": {200: {"description": "OK"}, 404: {"description": "Poll not found"}, 500: {"description": "Server error"}},
})
def vote_status(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role = _get_optional_jwt_identity()
    voter_token = request.args.get("voter_token")

    try:
        vote = None
        mode = "authenticated" if user_id else "anonymous"

        if user_id:
            vote = Vote.query.filter_by(poll_id=poll_id, user_id=user_id).first()
        else:
            if not voter_token:
                _safe_audit_read(
                    action="VOTE_STATUS_CHECKED",
                    entity_type="VOTE",
                    details={"poll_id": str(poll_id), "mode": "anonymous", "has_token": False, "result": "no_vote"},
                )
                return {"has_voted": False, "vote_id": None, "option_id": None}, 200

            secret = _get_anon_secret_or_raise()
            anon_token_hash = token_digest(voter_token, secret)
            vote = Vote.query.filter_by(poll_id=poll_id, anon_token_hash=anon_token_hash).first()

        has_voted = bool(vote)

        _safe_audit_read(
            action="VOTE_STATUS_CHECKED",
            entity_type="VOTE",
            entity_id=str(vote.id) if vote else None,
            details={"poll_id": str(poll_id), "mode": mode, "role": role, "has_voted": has_voted},
        )

        if not vote:
            return {"has_voted": False, "vote_id": None, "option_id": None}, 200

        return {"has_voted": True, "vote_id": str(vote.id), "option_id": str(vote.option_id)}, 200

    except KeyError:
        current_app.logger.exception("Voting configuration error (missing ANON_TOKEN_SECRET)")
        return {"message": "Voting service misconfigured"}, 500
    except SQLAlchemyError as e:
        current_app.logger.exception("DB error while checking vote status: %s", str(e))
        return {"message": "Failed to check vote status"}, 500

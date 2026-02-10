from flask import Blueprint, request, current_app
from flasgger import swag_from
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from flask_jwt_extended import (
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
)

from ...utils.audit import audit_log
from ...utils.validation import validate_or_abort
from ...extensions import db
from ...models.polls import Poll
from ...models.option import Option
from ...models.vote import Vote
from ...models.voter_token import VoterToken
from ...schemas.vote import VoteSubmitSchema
from ...utils.anon_token import generate_raw_token, token_digest  # deterministic HMAC

voting_bp = Blueprint("voting", __name__)
vote_submit_schema = VoteSubmitSchema()


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
    Best-effort audit for read-only endpoints (e.g. vote status).
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


@voting_bp.post("/<uuid:poll_id>/vote")
@swag_from({
    "tags": ["Voting"],
    "summary": "Submit a vote (authenticated or anonymous)",
    "parameters": [{
        "in": "body",
        "name": "body",
        "required": True,
        "schema": {
            "type": "object",
            "properties": {
                "option_id": {"type": "string", "example": "uuid"},
                "voter_token": {"type": "string", "example": "optional-token-for-anon"},
            },
            "required": ["option_id"],
        },
    }],
    "responses": {
        201: {"description": "Vote recorded"},
        400: {"description": "Validation error"},
        403: {"description": "Forbidden (poll not active / rules)"},
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
        # Optional: audit denied attempt (best-effort)
        _safe_audit_read(
            action="VOTE_SUBMIT_DENIED",
            entity_type="VOTE",
            details={"poll_id": str(poll_id), "reason": "poll_not_active", "status": poll.status},
        )
        return {"message": "Voting is not allowed on this poll"}, 403

    option_id = payload["option_id"]
    option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
    if not option:
        return {"message": "Option not found for this poll"}, 404

    user_id, role = _get_optional_jwt_identity()

    raw_token = payload.get("voter_token")
    issued_token = None

    try:
        secret = current_app.config["ANON_TOKEN_SECRET"]

        # ✅ One atomic transaction: vote (+ optional token issuance) + audit + commit
        with db.session.begin():
            if user_id:
                vote = Vote(poll_id=poll_id, option_id=option.id, user_id=user_id, anon_token_hash=None)
                db.session.add(vote)
                db.session.flush()  # ensure vote.id

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
                # Anonymous voter flow
                if not raw_token:
                    issued_token = generate_raw_token()
                    anon_token_hash = token_digest(issued_token, secret)

                    # Record issued token hash to support "one vote per token per poll"
                    db.session.add(VoterToken(poll_id=poll_id, token_hash=anon_token_hash))
                else:
                    anon_token_hash = token_digest(raw_token, secret)

                vote = Vote(poll_id=poll_id, option_id=option.id, user_id=None, anon_token_hash=anon_token_hash)
                db.session.add(vote)
                db.session.flush()  # ensure vote.id

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

        # No db.session.commit() needed here; db.session.begin() commits automatically on success.

    except IntegrityError:
        db.session.rollback()
        current_app.logger.info("Duplicate vote attempt", exc_info=False)

        # Optional: audit duplicate attempt (best-effort; do not change response)
        _safe_audit_read(
            action="VOTE_DUPLICATE_ATTEMPT",
            entity_type="VOTE",
            details={
                "poll_id": str(poll_id),
                "option_id": str(option.id),
                "user_id": str(user_id) if user_id else None,
                "mode": "authenticated" if user_id else "anonymous",
            },
        )

        return {"message": "You have already voted in this poll"}, 409

    except KeyError:
        # Missing ANON_TOKEN_SECRET config etc.
        db.session.rollback()
        current_app.logger.exception("Voting configuration error")
        return {"message": "Voting service misconfigured"}, 500

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error while submitting vote")
        return {"message": "Failed to record vote"}, 500

    except Exception:
        db.session.rollback()
        current_app.logger.exception("Unexpected error while submitting vote")
        return {"message": "Failed to record vote"}, 500

    response = {
        "message": "Vote recorded",
        "vote_id": str(vote.id),
        "poll_id": str(poll_id),
        "option_id": str(option.id),
    }
    if issued_token:
        response["voter_token"] = issued_token  # client must store this securely

    return response, 201


@voting_bp.get("/<uuid:poll_id>/vote/status")
@swag_from({
    "tags": ["Voting"],
    "summary": "Check vote status for current user or anonymous token",
    "parameters": [
        {"in": "query", "name": "voter_token", "required": False, "type": "string"},
    ],
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
                # Optional audit (best-effort)
                _safe_audit_read(
                    action="VOTE_STATUS_CHECKED",
                    entity_type="VOTE",
                    details={"poll_id": str(poll_id), "mode": "anonymous", "has_token": False, "result": "no_vote"},
                )
                return {"has_voted": False, "vote_id": None, "option_id": None}, 200

            secret = current_app.config["ANON_TOKEN_SECRET"]
            anon_token_hash = token_digest(voter_token, secret)
            vote = Vote.query.filter_by(poll_id=poll_id, anon_token_hash=anon_token_hash).first()

        has_voted = bool(vote)

        # Optional audit (best-effort)
        _safe_audit_read(
            action="VOTE_STATUS_CHECKED",
            entity_type="VOTE",
            entity_id=str(vote.id) if vote else None,
            details={
                "poll_id": str(poll_id),
                "mode": mode,
                "role": role,
                "has_voted": has_voted,
            },
        )

        if not vote:
            return {"has_voted": False, "vote_id": None, "option_id": None}, 200

        return {"has_voted": True, "vote_id": str(vote.id), "option_id": str(vote.option_id)}, 200

    except KeyError:
        current_app.logger.exception("Voting configuration error (missing ANON_TOKEN_SECRET)")
        return {"message": "Voting service misconfigured"}, 500
    except SQLAlchemyError:
        current_app.logger.exception("DB error while checking vote status")
        return {"message": "Failed to check vote status"}, 500

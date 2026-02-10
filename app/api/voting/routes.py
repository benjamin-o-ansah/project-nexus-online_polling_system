# from flask import Blueprint, request, current_app
# from flasgger import swag_from
# from sqlalchemy.exc import IntegrityError
# from flask_jwt_extended import (
#     jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
# )
# from ...utils.audit import audit_log
# from ...utils.validation import validate_or_abort

# from ...extensions import db
# from ...models.polls import Poll
# from ...models.option import Option
# from ...models.vote import Vote
# from ...models.voter_token import VoterToken
# from ...schemas.vote import VoteSubmitSchema
# from ...utils.anon_token import generate_raw_token, token_digest  # deterministic HMAC

# voting_bp = Blueprint("voting", __name__)
# vote_submit_schema = VoteSubmitSchema()


# def _get_optional_jwt_identity():
#     """
#     Allow both authenticated and anonymous requests.
#     Returns (user_id, role) or (None, None).
#     """
#     try:
#         verify_jwt_in_request(optional=True)
#         claims = get_jwt() or {}
#         return get_jwt_identity(), claims.get("role")
#     except Exception as e:
#         current_app.logger.debug(f"Optional JWT check failed: {e}")
#         return None, None


# @voting_bp.post("/<uuid:poll_id>/vote")
# @swag_from({
#     "tags": ["Voting"],
#     "summary": "Submit a vote (authenticated or anonymous)",
#     "parameters": [{
#         "in": "body",
#         "name": "body",
#         "required": True,
#         "schema": {
#             "type": "object",
#             "properties": {
#                 "option_id": {"type": "string", "example": "uuid"},
#                 "voter_token": {"type": "string", "example": "optional-token-for-anon"}
#             },
#             "required": ["option_id"]
#         }
#     }],
#     "responses": {
#         201: {"description": "Vote recorded"},
#         400: {"description": "Validation error"},
#         403: {"description": "Forbidden (poll not active / rules)"},
#         404: {"description": "Poll/Option not found"},
#         409: {"description": "Duplicate vote"}
#     }
# })
# def submit_vote(poll_id):
#     payload = request.get_json(silent=True) or {}
#     payload = validate_or_abort(vote_submit_schema, payload)

#     poll = Poll.query.get(poll_id)
#     if not poll:
#         return {"message": "Poll not found"}, 404

#     if poll.status != Poll.STATUS_ACTIVE:
#         return {"message": "Voting is not allowed on this poll"}, 403

#     option_id = payload["option_id"]
#     option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
#     if not option:
#         return {"message": "Option not found for this poll"}, 404

#     user_id, _role = _get_optional_jwt_identity()

#     raw_token = payload.get("voter_token")
#     anon_token_hash = None
#     issued_token = None

#     # Anonymous token flow (deterministic hashing)
#     if user_id:
#         vote = Vote(poll_id=poll_id, option_id=option.id, user_id=user_id, anon_token_hash=None)
#     else:
#         secret = current_app.config["ANON_TOKEN_SECRET"]
#         if not raw_token:
#             # Issue a new token for anonymous voter
#             issued_token = generate_raw_token()
#             anon_token_hash = token_digest(issued_token, secret)
#             db.session.add(VoterToken(poll_id=poll_id, token_hash=anon_token_hash))
#         else:
#             anon_token_hash = token_digest(raw_token, secret)

#         vote = Vote(poll_id=poll_id, option_id=option.id, user_id=None, anon_token_hash=anon_token_hash)

#     try:
#         with db.session.begin():  # single atomic transaction
#             db.session.add(vote)
#             db.session.flush()  # ensure vote.id is populated

#             audit_log(
#                 action="VOTE_SUBMITTED",
#                 entity_type="VOTE",
#                 entity_id=str(vote.id),
#                 details={"poll_id": str(poll_id), "option_id": str(option.id), "user_id": str(user_id) if user_id else None}
#             )
#         # transaction committed here
#     except IntegrityError:
#         # Unique constraint hit: user or anon token already voted
#         current_app.logger.info("Duplicate vote attempt", exc_info=False)
#         return {"message": "You have already voted in this poll"}, 409

#     response = {
#         "message": "Vote recorded",
#         "vote_id": str(vote.id),
#         "poll_id": str(poll_id),
#         "option_id": str(option.id),
#     }
#     if issued_token:
#         response["voter_token"] = issued_token  # client must store this securely

#     return response, 201


# @voting_bp.get("/<uuid:poll_id>/vote/status")
# @swag_from({
#     "tags": ["Voting"],
#     "summary": "Check vote status for current user or anonymous token",
#     "parameters": [
#         {"in": "query", "name": "voter_token", "required": False, "type": "string"}
#     ],
#     "responses": {200: {"description": "OK"}, 404: {"description": "Poll not found"}}
# })
# def vote_status(poll_id):
#     poll = Poll.query.get(poll_id)
#     if not poll:
#         return {"message": "Poll not found"}, 404

#     user_id, _role = _get_optional_jwt_identity()
#     voter_token = request.args.get("voter_token")

#     vote = None
#     if user_id:
#         vote = Vote.query.filter_by(poll_id=poll_id, user_id=user_id).first()
#     else:
#         if not voter_token:
#             return {"has_voted": False, "vote_id": None, "option_id": None}, 200

#         secret = current_app.config["ANON_TOKEN_SECRET"]
#         anon_token_hash = token_digest(voter_token, secret)
#         vote = Vote.query.filter_by(poll_id=poll_id, anon_token_hash=anon_token_hash).first()

#     if not vote:
#         return {"has_voted": False, "vote_id": None, "option_id": None}, 200

#     return {"has_voted": True, "vote_id": str(vote.id), "option_id": str(vote.option_id)}, 200

from flask import Blueprint, request, current_app
from flasgger import swag_from
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
)

from ...utils.audit import audit_log, secure_audit_log
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
        current_app.logger.debug(f"Optional JWT failed: {e}")
        return None, None


# ==========================================================
# SUBMIT VOTE
# ==========================================================
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
                "voter_token": {"type": "string", "example": "optional-token-for-anon"}
            },
            "required": ["option_id"]
        }
    }],
    "responses": {
        201: {"description": "Vote recorded"},
        400: {"description": "Validation error"},
        403: {"description": "Forbidden (poll not active)"},
        404: {"description": "Poll/Option not found"},
        409: {"description": "Duplicate vote"}
    }
})
def submit_vote(poll_id):
    payload = validate_or_abort(vote_submit_schema, request.get_json(silent=True) or {})

    # -------- Validate poll & option --------
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    if poll.status != Poll.STATUS_ACTIVE:
        secure_audit_log(
            "VOTE_REJECTED_INACTIVE_POLL",
            "VOTE",
            details={"poll_id": str(poll_id)}
        )
        return {"message": "Voting is not allowed on this poll"}, 403

    option = Option.query.filter_by(id=payload["option_id"], poll_id=poll_id).first()
    if not option:
        return {"message": "Option not found for this poll"}, 404

    # -------- Auth vs Anonymous flow --------
    user_id, _role = _get_optional_jwt_identity()
    raw_token = payload.get("voter_token")
    issued_token = None

    if user_id:
        # Authenticated vote
        vote = Vote(poll_id=poll_id, option_id=option.id, user_id=user_id, anon_token_hash=None)
    else:
        # Anonymous vote
        secret = current_app.config["ANON_TOKEN_SECRET"]

        # Issue token if no token provided
        if not raw_token:
            issued_token = generate_raw_token()
            token_hash = token_digest(issued_token, secret)
            db.session.add(VoterToken(poll_id=poll_id, token_hash=token_hash))
        else:
            token_hash = token_digest(raw_token, secret)

        vote = Vote(poll_id=poll_id, option_id=option.id, user_id=None, anon_token_hash=token_hash)

    # -------- Save vote atomically --------
    try:
        with db.session.begin():
            db.session.add(vote)
            db.session.flush()  # ensures vote.id is available

            audit_log(
                "VOTE_SUBMITTED",
                "VOTE",
                entity_id=str(vote.id),
                details={
                    "poll_id": str(poll_id),
                    "option_id": str(option.id),
                    "user_id": str(user_id) if user_id else None
                }
            )

    except IntegrityError:
        # Unique constraints detect duplicate vote
        secure_audit_log(
            "VOTE_DUPLICATE_ATTEMPT",
            "VOTE",
            details={"poll_id": str(poll_id), "user_id": str(user_id)}
        )
        return {"message": "You have already voted in this poll"}, 409

    response = {
        "message": "Vote recorded",
        "vote_id": str(vote.id),
        "poll_id": str(poll_id),
        "option_id": str(option.id),
    }
    if issued_token:
        response["voter_token"] = issued_token

    return response, 201


# ==========================================================
# CHECK VOTE STATUS
# ==========================================================
@voting_bp.get("/<uuid:poll_id>/vote/status")
@swag_from({
    "tags": ["Voting"],
    "summary": "Check vote status (authenticated or anonymous)",
    "parameters": [
        {"in": "query", "name": "voter_token", "required": False, "type": "string"}
    ],
    "responses": {
        200: {"description": "OK"},
        404: {"description": "Poll not found"}
    }
})
def vote_status(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, _role = _get_optional_jwt_identity()
    token = request.args.get("voter_token")

    vote = None

    # Authenticated user: check by user_id
    if user_id:
        vote = Vote.query.filter_by(poll_id=poll_id, user_id=user_id).first()

    else:
        # Anonymous flow
        if not token:
            return {"has_voted": False, "vote_id": None, "option_id": None}, 200

        secret = current_app.config["ANON_TOKEN_SECRET"]
        token_hash = token_digest(token, secret)
        vote = Vote.query.filter_by(poll_id=poll_id, anon_token_hash=token_hash).first()

    if not vote:
        return {"has_voted": False, "vote_id": None, "option_id": None}, 200

    return {"has_voted": True, "vote_id": str(vote.id), "option_id": str(vote.option_id)}, 200
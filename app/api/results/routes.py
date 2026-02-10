from flask import Blueprint, current_app
from flasgger import swag_from
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import (
    verify_jwt_in_request,
    get_jwt_identity,
    get_jwt,
)

from ...utils.audit import audit_log
from ...extensions import db
from ...models.polls import Poll
from ...models.option import Option
from ...models.vote import Vote

results_bp = Blueprint("results", __name__)


def _optional_jwt():
    """
    Allow both authenticated and unauthenticated access.
    Returns: (user_id, role) or (None, None)
    """
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt() or {}
        return get_jwt_identity(), claims.get("role")
    except Exception:
        return None, None


@results_bp.get("/<uuid:poll_id>/results")
@swag_from({
    "tags": ["Results"],
    "summary": "Get poll results (admin can view anytime; voters only after close)",
    "description": (
        "Access rules:\n"
        "- POLL_ADMIN (owner): can view results even while ACTIVE.\n"
        "- SYSTEM_ADMIN: can view anytime.\n"
        "- Voter/Anonymous: results are hidden until poll is CLOSED.\n"
        "Returns per-option vote counts and percentages."
    ),
    "responses": {
        200: {"description": "Results"},
        403: {"description": "Results not available yet / forbidden"},
        404: {"description": "Poll not found"},
        500: {"description": "Server error"},
    }
})
def poll_results(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role = _optional_jwt()

    # ---- Visibility rules (MVP) ----
    is_sys_admin = (role == "SYSTEM_ADMIN")
    is_owner_admin = (role == "POLL_ADMIN" and user_id and str(poll.owner_id) == str(user_id))
    can_view_anytime = is_owner_admin or is_sys_admin

    if not can_view_anytime and poll.status != Poll.STATUS_CLOSED:
        # Optional: audit denied attempt (best effort, do not block response)
        try:
            audit_log(
                action="POLL_RESULTS_VIEW_DENIED",
                entity_type="POLL",
                entity_id=str(poll.id),
                details={
                    "reason": "poll_not_closed",
                    "status": poll.status,
                    "role": role,
                    "is_authenticated": bool(user_id),
                },
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Audit logging failed: POLL_RESULTS_VIEW_DENIED")

        return {"message": "Results are not available yet"}, 403

    try:
        # ---- Aggregation query ----
        vote_counts = (
            db.session.query(
                Vote.option_id.label("option_id"),
                func.count(Vote.id).label("votes"),
            )
            .filter(Vote.poll_id == poll_id)
            .group_by(Vote.option_id)
            .all()
        )

        counts_map = {row.option_id: int(row.votes) for row in vote_counts}
        total_votes = sum(counts_map.values())

        # Include 0-vote options + stable ordering
        options = (
            Option.query
            .filter_by(poll_id=poll_id)
            .order_by(Option.created_at.asc())
            .all()
        )

        results = []
        for opt in options:
            v = counts_map.get(opt.id, 0)
            pct = (v / total_votes * 100.0) if total_votes > 0 else 0.0
            results.append({
                "option_id": str(opt.id),
                "option_text": opt.text,
                "votes": v,
                "percentage": round(pct, 2),
            })

        # ✅ Audit success (best practice: include actor context in details if audit_log doesn't do it globally)
        audit_log(
            action="POLL_RESULTS_VIEWED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={
                "status": poll.status,
                "total_votes": total_votes,
                "role": role,
                "is_authenticated": bool(user_id),
            },
        )
        db.session.commit()

        return {
            "poll_id": str(poll.id),
            "status": poll.status,
            "total_votes": total_votes,
            "results": results,
        }, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error fetching poll results")

        # Best-effort audit of failure (don’t fail if audit fails)
        try:
            audit_log(
                action="POLL_RESULTS_FETCH_FAILED",
                entity_type="POLL",
                entity_id=str(poll.id),
                details={"role": role, "is_authenticated": bool(user_id)},
            )
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Audit logging failed: POLL_RESULTS_FETCH_FAILED")

        return {"message": "Failed to fetch results"}, 500

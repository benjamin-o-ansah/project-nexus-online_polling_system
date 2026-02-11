from flask import Blueprint, request, current_app
from flasgger import swag_from
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from ...utils.audit import audit_log
from ...extensions import db
from ...models.polls import Poll
from ...models.option import Option
from ...schemas.poll import PollCreateSchema, PollUpdateSchema, PollReadSchema
from ...utils.rbac import roles_required
from ...utils.validation import validate_or_abort

polls_bp = Blueprint("polls", __name__)

poll_create_schema = PollCreateSchema()
poll_update_schema = PollUpdateSchema()
poll_read_schema = PollReadSchema()
poll_read_many_schema = PollReadSchema(many=True)


def _safe_audit_read(action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None):
    """
    Best-effort audit for read-only endpoints.
    We don't want read endpoints to fail if auditing fails, but we still try.
    """
    try:
        audit_log(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details or {},
        )
        db.session.commit()  # commit audit row only
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Audit logging failed (read endpoint): %s", action)

def _is_sys_admin(role: str | None) -> bool:
    return role == "SYSTEM_ADMIN"


def _is_owner_poll_admin(role: str | None, user_id, poll: Poll) -> bool:
    return role == "POLL_ADMIN" and user_id and str(poll.owner_id) == str(user_id)

def _assert_can_manage_poll(poll: Poll):
    """
    Allow POLL_ADMIN (owner) OR SYSTEM_ADMIN to manage (publish/close/delete/update).
    Returns (user_id, role, actor_type) for auditing.
    """
    role = (get_jwt() or {}).get("role")
    user_id = get_jwt_identity()

    if _is_sys_admin(role):
        return user_id, role, "SYSTEM_ADMIN"

    if _is_owner_poll_admin(role, user_id, poll):
        return user_id, role, "POLL_ADMIN_OWNER"

    return None, role, None


@polls_bp.post("/")
@jwt_required()
@roles_required("POLL_ADMIN", "SYSTEM_ADMIN")
@swag_from({
    "tags": ["Polls"],
    "summary": "Create a poll (poll admin or system admin)",
    "responses": {201: {"description": "Created"}, 400: {"description": "Validation error"}, 403: {"description": "Forbidden"}}
})
def create_poll():
    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(poll_create_schema, payload)

    owner_id = get_jwt_identity()
    role = (get_jwt() or {}).get("role")

    # If SYSTEM_ADMIN creates a poll, they become the owner by default (simple + consistent)
    poll = Poll(
        owner_id=owner_id,
        title=payload["title"].strip(),
        description=(payload.get("description") or None),
        status=Poll.STATUS_DRAFT
    )

    try:
        db.session.add(poll)
        db.session.flush()

        for opt in payload["options"]:
            db.session.add(Option(poll_id=poll.id, text=opt["text"].strip()))

        audit_log(
            action="POLL_CREATED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"title": poll.title, "created_by_role": role}
        )

        db.session.commit()
        return {"poll": poll_read_schema.dump(poll)}, 201

    except IntegrityError:
        db.session.rollback()
        return {"message": "Failed to create poll"}, 500
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error creating poll")
        return {"message": "Failed to create poll"}, 500


@polls_bp.get("/")
@jwt_required()
@swag_from({
    "tags": ["Polls"],
    "summary": "List polls",
    "description": "POLL_ADMIN sees own polls; SYSTEM_ADMIN sees all; others see active polls only.",
    "responses": {200: {"description": "OK"}, 401: {"description": "Unauthorized"}}
})
def list_polls():
    user_id = get_jwt_identity()
    role = (get_jwt() or {}).get("role")

    if role == "SYSTEM_ADMIN":
        polls = Poll.query.order_by(Poll.created_at.desc()).all()
        scope = "all"
    elif role == "POLL_ADMIN":
        polls = Poll.query.filter_by(owner_id=user_id).order_by(Poll.created_at.desc()).all()
        scope = "own"
    else:
        polls = Poll.query.filter_by(status=Poll.STATUS_ACTIVE).order_by(Poll.created_at.desc()).all()
        scope = "active_only"

    _safe_audit_read(
        action="POLLS_LISTED",
        entity_type="POLL",
        details={"role": role, "scope": scope, "count": len(polls)}
    )

    return {"polls": poll_read_many_schema.dump(polls)}, 200


@polls_bp.get("/<uuid:poll_id>")
@jwt_required()
@swag_from({"tags": ["Polls"], "summary": "Get poll details", "responses": {200: {}, 404: {}, 401: {}, 403: {}}})
def get_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    role = (get_jwt() or {}).get("role")
    user_id = get_jwt_identity()

    # SYSTEM_ADMIN can view everything (including drafts)
    if poll.status == Poll.STATUS_DRAFT and not (_is_sys_admin(role) or _is_owner_poll_admin(role, user_id, poll)):
        _safe_audit_read(
            action="POLL_VIEW_DENIED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"reason": "draft_poll_restricted"}
        )
        return {"message": "Not authorized to view this poll"}, 403

    _safe_audit_read(
        action="POLL_VIEWED",
        entity_type="POLL",
        entity_id=str(poll.id),
        details={"status": poll.status, "role": role}
    )

    return {"poll": poll_read_schema.dump(poll)}, 200


@polls_bp.put("/<uuid:poll_id>")
@jwt_required()
@roles_required("POLL_ADMIN", "SYSTEM_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Update poll (draft only) - owner poll admin or system admin", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def update_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role, actor_type = _assert_can_manage_poll(poll)
    if not actor_type:
        return {"message": "Forbidden"}, 403

    if not poll.can_edit():
        return {"message": "Poll cannot be edited after publishing"}, 400

    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(poll_update_schema, payload)

    try:
        if "title" in payload:
            poll.title = payload["title"].strip()
        if "description" in payload:
            poll.description = payload.get("description") or None

        if "options" in payload:
            poll.options.clear()
            db.session.flush()
            for opt in payload["options"]:
                db.session.add(Option(poll_id=poll.id, text=opt["text"].strip()))

        audit_log(
            action="POLL_UPDATED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"updated_fields": list(payload.keys()), "actor_role": role, "actor_type": actor_type}
        )

        db.session.commit()
        return {"poll": poll_read_schema.dump(poll)}, 200

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error updating poll")
        return {"message": "Failed to update poll"}, 500


@polls_bp.post("/<uuid:poll_id>/publish")
@jwt_required()
@roles_required("POLL_ADMIN", "SYSTEM_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Publish poll (draft -> active) - owner poll admin or system admin", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def publish_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role, actor_type = _assert_can_manage_poll(poll)
    if not actor_type:
        return {"message": "Forbidden"}, 403

    try:
        poll.publish()

        audit_log(
            action="POLL_PUBLISHED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={
                "from_status": Poll.STATUS_DRAFT,
                "to_status": Poll.STATUS_ACTIVE,
                "actor_role": role,
                "actor_type": actor_type,
            }
        )

        db.session.commit()
        return {"poll": poll_read_schema.dump(poll)}, 200

    except ValueError as e:
        db.session.rollback()
        return {"message": str(e)}, 400
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error publishing poll")
        return {"message": "Failed to publish poll"}, 500


@polls_bp.post("/<uuid:poll_id>/close")
@jwt_required()
@roles_required("POLL_ADMIN", "SYSTEM_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Close poll (active -> closed) - owner poll admin or system admin", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def close_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role, actor_type = _assert_can_manage_poll(poll)
    if not actor_type:
        return {"message": "Forbidden"}, 403

    try:
        poll.close()

        audit_log(
            action="POLL_CLOSED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"to_status": Poll.STATUS_CLOSED, "actor_role": role, "actor_type": actor_type}
        )

        db.session.commit()
        return {"poll": poll_read_schema.dump(poll)}, 200

    except ValueError as e:
        db.session.rollback()
        return {"message": str(e)}, 400
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error closing poll")
        return {"message": "Failed to close poll"}, 500


@polls_bp.delete("/<uuid:poll_id>")
@jwt_required()
@roles_required("POLL_ADMIN", "SYSTEM_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Delete poll - owner poll admin or system admin", "responses": {204: {}, 403: {}, 404: {}}})
def delete_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id, role, actor_type = _assert_can_manage_poll(poll)
    if not actor_type:
        return {"message": "Forbidden"}, 403

    try:
        audit_log(
            action="POLL_DELETED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"title": poll.title, "actor_role": role, "actor_type": actor_type}
        )

        db.session.delete(poll)
        db.session.commit()
        return {"message": "Poll deleted successfully", "success": "ok", "status": "deleted"}, 204

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DB error deleting poll")
        return {"message": "Failed to delete poll"}, 500


@polls_bp.get("/voter/active")
@jwt_required()
@roles_required("VOTER")
@swag_from({
    "tags": ["Polls"],
    "summary": "VOTER: List ACTIVE polls",
    "responses": {200: {"description": "OK"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}}
})
def list_active_polls_for_voter():
    role = (get_jwt() or {}).get("role")

    polls = (
        Poll.query
        .filter_by(status=Poll.STATUS_ACTIVE)
        .order_by(Poll.created_at.desc())
        .all()
    )

    _safe_audit_read(
        action="VOTER_ACTIVE_POLLS_LISTED",
        entity_type="POLL",
        details={"role": role, "scope": "active", "count": len(polls)}
    )

    return {"polls": poll_read_many_schema.dump(polls)}, 200


@polls_bp.get("/voter/closed")
@jwt_required()
@roles_required("VOTER")
@swag_from({
    "tags": ["Polls"],
    "summary": "VOTER: List CLOSED polls",
    "responses": {200: {"description": "OK"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}}
})
def list_closed_polls_for_voter():
    role = (get_jwt() or {}).get("role")

    polls = (
        Poll.query
        .filter_by(status=Poll.STATUS_CLOSED)
        .order_by(Poll.closed_at.desc())
        .all()
    )

    _safe_audit_read(
        action="VOTER_CLOSED_POLLS_LISTED",
        entity_type="POLL",
        details={"role": role, "scope": "closed", "count": len(polls)}
    )

    return {"polls": poll_read_many_schema.dump(polls)}, 200
from flask import Blueprint, request
from flasgger import swag_from
from flask_jwt_extended import jwt_required, get_jwt_identity,get_jwt
from sqlalchemy.exc import IntegrityError
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


@polls_bp.post("/")
@jwt_required()
@roles_required("POLL_ADMIN")
@swag_from({
    "tags": ["Polls"],
    "summary": "Create a poll (admin only)",
    "parameters": [{
        "in": "body",
        "name": "body",
        "required": True,
        "schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "example": "Best Programming Language?"},
                "description": {"type": "string", "example": "Vote for your favorite."},
                "options": {"type": "array", "items": {"type": "object", "properties": {"text": {"type": "string"}}}}
            },
            "required": ["title", "options"]
        }
    }],
    "responses": {201: {"description": "Created"}, 400: {"description": "Validation error"}, 403: {"description": "Forbidden"}}
})
def create_poll():
    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(poll_create_schema, payload)

    owner_id = get_jwt_identity()
    poll = Poll(
        owner_id=owner_id,
        title=payload["title"].strip(),
        description=(payload.get("description") or None),
        status=Poll.STATUS_DRAFT
    )

    db.session.add(poll)
    db.session.flush()  # so poll.id is available

    for opt in payload["options"]:
        db.session.add(Option(poll_id=poll.id, text=opt["text"].strip()))

    try:
        db.session.commit()
        audit_log(
            action="POLL_CREATED",
            entity_type="POLL",
            entity_id=str(poll.id),
            details={"title": poll.title}
                )

    except IntegrityError:
        db.session.rollback()
        return {"message": "Failed to create poll"}, 500

    return {"poll": poll_read_schema.dump(poll)}, 201


@polls_bp.get("/")
@jwt_required()
@swag_from({
    "tags": ["Polls"],
    "summary": "List polls",
    "description": "Admins see their own polls; other roles see active polls only (can be adjusted).",
    "responses": {200: {"description": "OK"}, 401: {"description": "Unauthorized"}}
})
def list_polls():
    user_id = get_jwt_identity()
    # For MVP simplicity:
    # - POLL_ADMIN sees own polls
    # - Others see ACTIVE polls
    role = get_jwt().get("role")

    if role == "POLL_ADMIN":
        polls = Poll.query.filter_by(owner_id=user_id).order_by(Poll.created_at.desc()).all()
    else:
        polls = Poll.query.filter_by(status=Poll.STATUS_ACTIVE).order_by(Poll.created_at.desc()).all()

    return {"polls": poll_read_many_schema.dump(polls)}, 200


@polls_bp.get("/<uuid:poll_id>")
@jwt_required()
@swag_from({"tags": ["Polls"], "summary": "Get poll details", "responses": {200: {}, 404: {}, 401: {}}})
def get_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    # Optional: restrict who can view draft polls
    role = get_jwt().get("role")
    user_id = get_jwt_identity()

    if poll.status == Poll.STATUS_DRAFT and not (role == "POLL_ADMIN" and str(poll.owner_id) == str(user_id)):
        return {"message": "Not authorized to view this poll"}, 403

    return {"poll": poll_read_schema.dump(poll)}, 200


@polls_bp.put("/<uuid:poll_id>")
@jwt_required()
@roles_required("POLL_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Update poll (draft only)", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def update_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id = get_jwt_identity()
    if str(poll.owner_id) != str(user_id):
        return {"message": "Forbidden"}, 403

    if not poll.can_edit():
        return {"message": "Poll cannot be edited after publishing"}, 400

    payload = request.get_json(silent=True) or {}
    payload = validate_or_abort(poll_update_schema, payload)
    
    if "title" in payload:
        poll.title = payload["title"].strip()
    if "description" in payload:
        poll.description = payload.get("description") or None

    # MVP: if options provided, replace them
    if "options" in payload:
        poll.options.clear()
        db.session.flush()
        for opt in payload["options"]:
            db.session.add(Option(poll_id=poll.id, text=opt["text"].strip()))

    db.session.commit()
    audit_log(
    action="POLL_UPDATED",
    entity_type="POLL",
    entity_id=str(poll.id),
    details={"updated_fields": list(payload.keys())}
)

    return {"poll": poll_read_schema.dump(poll)}, 200


@polls_bp.post("/<uuid:poll_id>/publish")
@jwt_required()
@roles_required("POLL_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Publish poll (draft -> active)", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def publish_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id = get_jwt_identity()
    if str(poll.owner_id) != str(user_id):
        return {"message": "Forbidden"}, 403

    try:
        poll.publish()
    except ValueError as e:
        return {"message": str(e)}, 400

    db.session.commit()
    audit_log(
    action="POLL_PUBLISHED",
    entity_type="POLL",
    entity_id=str(poll.id),
)

    return {"poll": poll_read_schema.dump(poll)}, 200


@polls_bp.post("/<uuid:poll_id>/close")
@jwt_required()
@roles_required("POLL_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Close poll (active -> closed)", "responses": {200: {}, 400: {}, 403: {}, 404: {}}})
def close_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id = get_jwt_identity()
    if str(poll.owner_id) != str(user_id):
        return {"message": "Forbidden"}, 403

    try:
        poll.close()
    except ValueError as e:
        return {"message": str(e)}, 400

    db.session.commit()
    audit_log(
    action="POLL_CLOSED",
    entity_type="POLL",
    entity_id=str(poll.id),
)

    return {"poll": poll_read_schema.dump(poll)}, 200


@polls_bp.delete("/<uuid:poll_id>")
@jwt_required()
@roles_required("POLL_ADMIN")
@swag_from({"tags": ["Polls"], "summary": "Delete poll", "responses": {204: {}, 403: {}, 404: {}}})
def delete_poll(poll_id):
    poll = Poll.query.get(poll_id)
    if not poll:
        return {"message": "Poll not found"}, 404

    user_id = get_jwt_identity()
    if str(poll.owner_id) != str(user_id):
        return {"message": "Forbidden"}, 403
    audit_log(
    action="POLL_DELETED",
    entity_type="POLL",
    entity_id=str(poll.id),
)
    db.session.delete(poll)
    db.session.commit()
    

    return {"message": "Poll deleted successfully", "success": "ok", "status": "deleted"}, 204

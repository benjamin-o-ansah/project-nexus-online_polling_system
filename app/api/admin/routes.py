from datetime import datetime, timedelta
from flask import Blueprint, request, current_app
from flasgger import swag_from
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

from ...extensions import db
from ...utils.rbac import roles_required
from ...utils.audit import audit_log
from ...models.user import User
from ...models.polls import Poll
from ...models.vote import Vote
from ...models.audit_log import AuditLog

admin_bp = Blueprint("admin", __name__)


def _safe_audit(action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None):
    """
    Best-effort audit so admin read endpoints won't fail if auditing fails.
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
        current_app.logger.exception("Audit logging failed: %s", action)


def _parse_iso(s: str) -> datetime:
    """
    Accepts:
      - 'YYYY-MM-DDTHH:MM:SS'
      - 'YYYY-MM-DDTHH:MM:SSZ'
      - 'YYYY-MM-DDTHH:MM:SS+00:00'
    Returns a naive datetime (UTC if timezone provided).
    """
    s = (s or "").strip()
    if not s:
        raise ValueError("Empty datetime string")

    # Normalize Zulu
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    dt = datetime.fromisoformat(s)
    # Convert aware -> naive UTC for consistent DB comparisons if your DB stores naive UTC
    if dt.tzinfo is not None:
        dt = dt.astimezone(tz=datetime.timezone.utc).replace(tzinfo=None)  # type: ignore[attr-defined]
    return dt


@admin_bp.get("/metrics")
@jwt_required()
@roles_required("SYSTEM_ADMIN")
@swag_from({
    "tags": ["Admin"],
    "summary": "Platform usage metrics (system admin only)",
    "responses": {200: {"description": "Metrics"}, 403: {"description": "Forbidden"}}
})
def metrics():
    now = datetime.utcnow()
    since_24h = now - timedelta(hours=24)

    total_users = db.session.query(func.count(User.id)).scalar() or 0
    total_polls = db.session.query(func.count(Poll.id)).scalar() or 0
    total_votes = db.session.query(func.count(Vote.id)).scalar() or 0

    active_polls = db.session.query(func.count(Poll.id)).filter(Poll.status == Poll.STATUS_ACTIVE).scalar() or 0
    closed_polls = db.session.query(func.count(Poll.id)).filter(Poll.status == Poll.STATUS_CLOSED).scalar() or 0
    draft_polls = db.session.query(func.count(Poll.id)).filter(Poll.status == Poll.STATUS_DRAFT).scalar() or 0

    votes_last_24h = db.session.query(func.count(Vote.id)).filter(Vote.created_at >= since_24h).scalar() or 0
    polls_created_last_24h = db.session.query(func.count(Poll.id)).filter(Poll.created_at >= since_24h).scalar() or 0

    audit_events_last_24h = (
        db.session.query(func.count(AuditLog.id))
        .filter(AuditLog.created_at >= since_24h)
        .scalar()
        or 0
    )

    # Best-effort audit (don’t break metrics if audit fails)
    _safe_audit(
        action="ADMIN_METRICS_VIEWED",
        entity_type="ADMIN",
        details={
            "user_id": str(get_jwt_identity()),
            "role": (get_jwt() or {}).get("role"),
        },
    )

    return {
        "timestamp": now.isoformat() + "Z",
        "users": {"total": total_users},
        "polls": {
            "total": total_polls,
            "draft": draft_polls,
            "active": active_polls,
            "closed": closed_polls,
            "created_last_24h": polls_created_last_24h,
        },
        "votes": {"total": total_votes, "submitted_last_24h": votes_last_24h},
        "audit": {"events_last_24h": audit_events_last_24h},
    }, 200


@admin_bp.get("/audit-logs")
@jwt_required()
@roles_required("SYSTEM_ADMIN")
@swag_from({
    "tags": ["Admin"],
    "summary": "Query audit logs (system admin only)",
    "parameters": [
        {"in": "query", "name": "action", "type": "string", "required": False},
        {"in": "query", "name": "entity_type", "type": "string", "required": False},
        {"in": "query", "name": "from", "type": "string", "required": False, "description": "ISO date-time"},
        {"in": "query", "name": "to", "type": "string", "required": False, "description": "ISO date-time"},
        {"in": "query", "name": "limit", "type": "integer", "required": False, "default": 50},
        {"in": "query", "name": "offset", "type": "integer", "required": False, "default": 0},
    ],
    "responses": {200: {"description": "Logs"}, 400: {"description": "Bad request"}, 403: {"description": "Forbidden"}}
})
def audit_logs():
    action = request.args.get("action")
    entity_type = request.args.get("entity_type")
    from_dt = request.args.get("from")
    to_dt = request.args.get("to")

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return {"message": "Invalid limit/offset"}, 400

    q = AuditLog.query

    if action:
        q = q.filter(AuditLog.action == action)
    if entity_type:
        q = q.filter(AuditLog.entity_type == entity_type)

    try:
        if from_dt:
            q = q.filter(AuditLog.created_at >= _parse_iso(from_dt))
        if to_dt:
            q = q.filter(AuditLog.created_at <= _parse_iso(to_dt))
    except ValueError:
        return {"message": "Invalid from/to datetime. Use ISO format."}, 400

    try:
        total = q.count()
        logs = (
            q.order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
    except SQLAlchemyError:
        current_app.logger.exception("DB error querying audit logs")
        return {"message": "Failed to query audit logs"}, 500

    # Best-effort audit (don’t break audit viewing if audit fails)
    _safe_audit(
        action="ADMIN_AUDIT_LOGS_VIEWED",
        entity_type="ADMIN",
        details={
            "user_id": str(get_jwt_identity()),
            "role": (get_jwt() or {}).get("role"),
            "filters": {
                "action": action,
                "entity_type": entity_type,
                "from": from_dt,
                "to": to_dt,
                "limit": limit,
                "offset": offset,
            },
            "result_count": len(logs),
            "total": total,
        },
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": [
            {
                "id": str(l.id),
                "created_at": l.created_at.isoformat() + "Z",
                "actor_user_id": str(l.actor_user_id) if l.actor_user_id else None,
                "actor_role": l.actor_role,
                "action": l.action,
                "entity_type": l.entity_type,
                "entity_id": str(l.entity_id) if l.entity_id else None,
                "ip_address": l.ip_address,
                "user_agent": l.user_agent,
                "details": l.details,
            }
            for l in logs
        ],
    }, 200


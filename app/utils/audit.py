from typing import Optional, Dict, Any
from flask import request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt

from ..extensions import db
from ..models.audit_log import AuditLog

def _optional_actor():
    """
    Returns (user_id, role) or (None, None).
    Works for both authenticated and anonymous requests.
    """
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        return get_jwt_identity(), claims.get("role")
    except Exception:
        return None, None

def audit_log(
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    user_id, role = _optional_actor()

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent")

    log = AuditLog(
        actor_user_id=user_id if user_id else None,
        actor_role=role,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id if entity_id else None,
        ip_address=ip,
        user_agent=ua[:255] if ua else None,
        details=details or None,
    )
    db.session.add(log)

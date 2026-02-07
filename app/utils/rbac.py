from functools import wraps
from flask import abort
from flask_jwt_extended import get_jwt

def roles_required(*allowed_roles: str):
    """
    Require JWT and restrict endpoint access to specific roles.
    Use with @jwt_required() above it.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role")
            if role not in allowed_roles:
                abort(403, description="Insufficient permissions")
            return fn(*args, **kwargs)
        return wrapper
    return decorator

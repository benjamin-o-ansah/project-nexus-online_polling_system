from flask import jsonify, g
from werkzeug.exceptions import HTTPException

def _payload(code: str, message: str, details=None, status=400):
    return (
        jsonify({
            "success": False,
            "error": {
                "code": code,
                "message": message,
                "details": details or None,
            },
            "request_id": getattr(g, "request_id", None),
        }),
        status,
    )

def register_error_handlers(app):
    # Marshmallow validation errors: we’ll standardize manually (see below)
    # Generic HTTP errors (404, 403, 401, etc.)
    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        desc = e.description

        # If we pass structured error info via abort(description=dict)
        if isinstance(desc, dict):
            code = desc.get("code") or e.name.replace(" ", "_").upper()
            message = desc.get("message") or e.name
            details = desc.get("errors") or desc.get("details")
            return _payload(code=code, message=message, details=details, status=e.code or 400)

        return _payload(
            code=e.name.replace(" ", "_").upper(),
            message=desc or e.name,
            details=None,
            status=e.code or 400
        )

    @app.errorhandler(404)
    def handle_404(_):
        return _payload("NOT_FOUND", "Resource not found", status=404)

    @app.errorhandler(500)
    def handle_500(_):
        # Don't leak internals
        return _payload("INTERNAL_SERVER_ERROR", "An unexpected error occurred", status=500)

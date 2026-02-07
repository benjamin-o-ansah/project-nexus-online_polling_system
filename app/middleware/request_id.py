import uuid
from flask import g, request

def init_request_id(app):
    @app.before_request
    def _assign_request_id():
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        g.request_id = rid

    @app.after_request
    def _add_request_id_header(response):
        if hasattr(g, "request_id"):
            response.headers["X-Request-Id"] = g.request_id
        return response

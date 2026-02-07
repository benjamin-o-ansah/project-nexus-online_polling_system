from dotenv import load_dotenv
from .errors import register_error_handlers
from flask import Flask
from .config import Config
from .extensions import db, migrate, jwt, ma, swagger, mail
from .models.token_blocklist import TokenBlocklist
from flasgger import Swagger
from .swagger_config import swagger_template
from .middleware.request_id import init_request_id

load_dotenv()

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    Swagger(app, template=swagger_template(app))
    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    ma.init_app(app)
    # swagger.init_app(app)
    mail.init_app(app)

    # Middleware + errors
    init_request_id(app)
    register_error_handlers(app)

    # Blueprint imports
    from .api.auth.routes import auth_bp
    from .api.poll.routes import polls_bp
    from .api.voting.routes import voting_bp
    from .api.results.routes import results_bp
    from .api.admin.routes import admin_bp

    # Blueprints
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(polls_bp, url_prefix="/api/polls")
    app.register_blueprint(voting_bp, url_prefix="/api/polls")
    app.register_blueprint(results_bp, url_prefix="/api/polls")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    @app.before_request
    def assign_request_id():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def attach_request_id(response):
        response.headers["X-Request-Id"] = getattr(g, "request_id", "")
        return response

    @app.errorhandler(Exception)
    def handle_exception(e):
        # Always log full traceback with request_id
        app.logger.exception("Unhandled exception request_id=%s path=%s", getattr(g, "request_id", None), request.path)

        if isinstance(e, HTTPException):
            return {
                "success": False,
                "error": {
                    "code": e.name.upper().replace(" ", "_"),
                    "message": e.description if isinstance(e.description, str) else "Request error",
                    "details": getattr(e, "description", None) if isinstance(e.description, dict) else None,
                },
                "request_id": getattr(g, "request_id", None)
            }, e.code

    return {
        "success": False,
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "details": None
        },
        "request_id": getattr(g, "request_id", None)
    }, 500

    # Health check
    @app.get("/health")
    def health():
        return {"status": "ok"}, 200
        # JWT token revocation check

    @jwt.token_in_blocklist_loader
    def is_token_revoked(jwt_header, jwt_payload) -> bool:
        jti = jwt_payload.get("jti")
        if not jti:
            return True
        return TokenBlocklist.is_blocklisted(jti)
    
    

    return app

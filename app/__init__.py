from dotenv import load_dotenv
from .errors import register_error_handlers
from flask import Flask
import os
from .config import Config
from .extensions import db, migrate, jwt, ma
from .models.token_blocklist import TokenBlocklist
from flasgger import Swagger
from .swagger_config import swagger_template
from .middleware.request_id import init_request_id
from flask_cors import CORS

load_dotenv()
origins = os.getenv("CORS_ORIGINS", "https://projectnexuspolling.vercel.app").split(",")
def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    CORS(
        app,
      
        resources={r"/api/*": {"origins": [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "https://projectnexuspolling.vercel.app",
            "https://bbe6006a-f81d-42fe-8f11-39b51d681b25.lovableproject.com",
            "https://id-preview--bbe6006a-f81d-42fe-8f11-39b51d681b25.lovable.app",

        ]}},
        supports_credentials=True,
        allow_headers=[
            "Content-Type",
            "Authorization",
        ],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    Swagger(app, template=swagger_template(app))
    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    ma.init_app(app)
    # swagger.init_app(app)
    # mail.init_app(app)

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
    

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        try:
            if exception:
                db.session.rollback()
        finally:
            db.session.remove()
    

    return app

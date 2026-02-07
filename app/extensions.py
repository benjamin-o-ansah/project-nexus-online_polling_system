from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flasgger import Swagger
from flask_mail import Mail
# from .swagger_config import swagger_template

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
ma = Marshmallow()
swagger = Swagger()
# swagger = Swagger(template = swagger_template())
mail = Mail()

def swagger_template(app=None):
    title = "Online Polling System API"
    version = "1.0.0"

    if app:
        title = app.config.get("SWAGGER_TITLE", title)
        version = app.config.get("SWAGGER_VERSION", version)

    return {
        "swagger": "2.0",
        "info": {"title": title, "version": version},
        "securityDefinitions": {
            "BearerAuth": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header: Bearer <token>"
            }
        },
        "definitions": {
            "ErrorResponse": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean", "example": False},
                    "error": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "example": "VALIDATION_ERROR"},
                            "message": {"type": "string", "example": "Validation error"},
                            "details": {"type": "object"}
                        }
                    },
                    "request_id": {"type": "string"}
                }
            }
        }
    }

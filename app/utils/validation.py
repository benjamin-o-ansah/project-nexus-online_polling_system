from flask import abort

def validate_or_abort(schema, payload):
    errors = schema.validate(payload)
    if errors:
        abort(
            400,
            description={
                "code": "VALIDATION_ERROR",
                "message": "Validation error",
                "errors": errors,
            },
        )
    return payload

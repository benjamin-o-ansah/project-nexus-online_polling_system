from marshmallow import Schema, fields, validate

class RegisterSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    role = fields.Str(required=False, validate=validate.OneOf(["POLL_ADMIN", "VOTER", "SYSTEM_ADMIN"]))

class LoginSchema(Schema):
    """Schema for login request"""
    email = fields.Email(required=True)
    password = fields.Str(
        required=True, 
        validate=validate.Length(min=8, max=128),
    )

# Use this schema in your route
# class LoginRequestOTPSchema(Schema):
#     email = fields.Email(required=True)
#     password = fields.Str(required=True, validate=validate.Length(min=6, max=128))

# class LoginVerifyOTPSchema(Schema):
#     challenge_id = fields.UUID(required=True)
#     otp = fields.Str(required=True, validate=validate.Regexp(r"^\d{6}$", error="OTP must be 6 digits"))

class RefreshSchema(Schema):
    # refresh token is in Authorization header normally; kept empty for doc simplicity
    pass

class MessageSchema(Schema):
    message = fields.Str(required=True)

class TokenSchema(Schema):
    access_token = fields.Str(required=True)
    refresh_token = fields.Str(required=True)
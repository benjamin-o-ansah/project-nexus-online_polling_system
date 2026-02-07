from marshmallow import Schema, fields

class UserSchema(Schema):
    id = fields.UUID()
    email = fields.Email()
    role = fields.Str()
    is_active = fields.Bool()
    created_at = fields.DateTime()

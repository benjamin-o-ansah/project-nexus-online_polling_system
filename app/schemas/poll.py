from marshmallow import Schema, fields, validate, validates_schema, ValidationError

class OptionCreateSchema(Schema):
    text = fields.Str(required=True, validate=validate.Length(min=1, max=200))

class PollCreateSchema(Schema):
    title = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    description = fields.Str(required=False, allow_none=True)
    options = fields.List(fields.Nested(OptionCreateSchema), required=True, validate=validate.Length(min=2))

class PollUpdateSchema(Schema):
    title = fields.Str(required=False, validate=validate.Length(min=1, max=200))
    description = fields.Str(required=False, allow_none=True)
    options = fields.List(fields.Nested(OptionCreateSchema), required=False, validate=validate.Length(min=2))

    @validates_schema
    def at_least_one_field(self, data, **kwargs):
        if not data:
            raise ValidationError("At least one field must be provided")

class OptionReadSchema(Schema):
    id = fields.UUID()
    text = fields.Str()
    created_at = fields.DateTime()

class PollReadSchema(Schema):
    id = fields.UUID()
    owner_id = fields.UUID()
    title = fields.Str()
    description = fields.Str(allow_none=True)
    status = fields.Str()
    created_at = fields.DateTime()
    updated_at = fields.DateTime()
    published_at = fields.DateTime(allow_none=True)
    closed_at = fields.DateTime(allow_none=True)
    options = fields.List(fields.Nested(OptionReadSchema))

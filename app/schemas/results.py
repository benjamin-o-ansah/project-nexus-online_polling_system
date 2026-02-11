from marshmallow import Schema, fields

class OptionResultSchema(Schema):
    option_id = fields.UUID(required=True)
    option_text = fields.Str(required=True)
    votes = fields.Int(required=True)
    percentage = fields.Float(required=True)

class PollResultsSchema(Schema):
    poll_id = fields.UUID(required=True)
    status = fields.Str(required=True)
    total_votes = fields.Int(required=True)
    results = fields.List(fields.Nested(OptionResultSchema), required=True)

class PollResultsWithMetaSchema(PollResultsSchema):
    title = fields.Str(required=True)
    description = fields.Str(allow_none=True)
    closed_at = fields.DateTime(allow_none=True)

# ✅ New: response wrapper for "all closed poll results"
class ClosedPollResultsListSchema(Schema):
    count = fields.Int(required=True)
    polls = fields.List(fields.Nested(PollResultsWithMetaSchema), required=True)
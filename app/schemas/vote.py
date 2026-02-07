from marshmallow import Schema, fields

class VoteSubmitSchema(Schema):
    option_id = fields.UUID(required=True)
    # For anonymous voting (optional if JWT present)
    voter_token = fields.Str(required=False, allow_none=True)

class VoteStatusSchema(Schema):
    has_voted = fields.Bool(required=True)
    vote_id = fields.UUID(allow_none=True)
    option_id = fields.UUID(allow_none=True)

class VoteReceiptSchema(Schema):
    message = fields.Str(required=True)
    vote_id = fields.UUID()
    poll_id = fields.UUID()
    option_id = fields.UUID()
    voter_token = fields.Str(allow_none=True)  # returned for anonymous voters

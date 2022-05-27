import mongoengine as me


class User(me.Document):

    user_id = me.StringField(required=True)
    username = me.StringField(required=True)
    hashed_password = me.StringField(required=True)
    active_two_fa_option = me.StringField(required=True)
    active_challenge = me.StringField()
    certificate = me.StringField()

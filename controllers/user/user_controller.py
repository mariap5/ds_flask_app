from models.user import User


def index(user_id):
    user = User.objects(user_id=user_id).first()
    return {
        "username": user.username,
        "user_id": user.user_id,
    }

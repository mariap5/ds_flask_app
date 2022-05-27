from flask import Blueprint

from controllers.user.user_controller import index

user_blueprint = Blueprint('user_blueprint', __name__)

user_blueprint.route('/<user_id>', methods=['GET'])(index)
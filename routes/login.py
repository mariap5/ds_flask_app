from flask import Blueprint

from controllers.login.login_controller import index, login, solve_challenge

login_blueprint = Blueprint('login_blueprint', __name__)

login_blueprint.route('/', methods=['GET'])(index)
login_blueprint.route('/', methods=['POST'])(login)
login_blueprint.route('/challenge', methods=['POST'])(solve_challenge)

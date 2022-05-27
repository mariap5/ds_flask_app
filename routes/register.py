from flask import Blueprint

from controllers.register.register_controller import index, register, register_usb_token, serve_register_usb_token

register_blueprint = Blueprint('register_blueprint', __name__)

register_blueprint.route('/', methods=['GET'])(index)
register_blueprint.route('/', methods=['POST'])(register)
register_blueprint.route('/register-usb-token', methods=['GET'])(serve_register_usb_token)
register_blueprint.route('/register-usb-token', methods=['POST'])(register_usb_token)

from flask import Blueprint

from controllers.document.document import upload_document, sign_document, verify_signature

sign_document_blueprint = Blueprint('sign_document_blueprint', __name__)

sign_document_blueprint.route('/sign', methods=['GET'])(sign_document)
sign_document_blueprint.route('/upload', methods=['GET'])(upload_document)
sign_document_blueprint.route('/verify-signature', methods=['POST'])(verify_signature)

import codecs

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import render_template, request, jsonify

from exceptions.error_response import ErrorResponse
from models.user import User


def sign_document():
    return render_template('sign_document.html')


def upload_document():
    return render_template('upload_document.html')


def verify_signature():
    document_content = request.json.get('document_content')
    document_signature = request.json.get('document_signature')
    user_id = request.json.get("user_id")
    user = User.objects(user_id=user_id).first()
    cert = x509.load_pem_x509_certificate(bytes(user.certificate, 'utf-8'))
    public_key_pem = cert.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)

    hashed_message = SHA256.new(bytes(document_content, 'ascii'))
    public_key = RSA.import_key(public_key_pem)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hashed_message, codecs.decode(bytes(document_signature, "ascii"), "base64"))
        return jsonify({
            "message": "The signature is valid",
            "valid": True
        })
    except ValueError as e:
        return ErrorResponse(400, "The signature is not valid").to_dict(), 400

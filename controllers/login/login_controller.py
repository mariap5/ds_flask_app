import codecs
import uuid

import bcrypt
import jwt
from Crypto.Signature import pkcs1_15
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from flask import render_template, request, jsonify
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from exceptions.error_response import ErrorResponse
from models.user import User

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def index():
    return render_template('login.html')


def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username == '' or password == '':
        return ErrorResponse(400, "You must provide an username and a password").to_dict(), 400
    user = User.objects(username=username).first()
    if user is None:
        return ErrorResponse(400, "Username or password is incorrect").to_dict(), 400
    if bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
        challenge = str(uuid.uuid4())
        user.update(active_challenge=challenge)
        # encoded_jwt = jwt.encode(
        #     {
        #         "username": user.username,
        #         "user_id": user.user_id,
        #         "two_factor_auth": "inactive" if user.certificate is None else "active",
        #         "identity_verified": False
        #     },
        #     "secret",
        #     algorithm="HS256"
        # )

        return {
            "challenge": challenge,
            "user_id": user.user_id
        }
    else:
        return ErrorResponse(400, "Username or password is incorrect").to_dict(), 400


def solve_challenge():
    encrypted_challenge = request.json.get("encrypted_challenge")
    user_id = request.json.get("user_id")
    user = User.objects(user_id=user_id).first()
    cert = x509.load_pem_x509_certificate(bytes(user.certificate, 'utf-8'))
    public_key_pem = cert.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)

    hashed_message = SHA256.new(bytes(user.active_challenge, 'ascii'))
    public_key = RSA.import_key(public_key_pem)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hashed_message, codecs.decode(bytes(encrypted_challenge, "ascii"), "base64"))
        encoded_jwt = jwt.encode(
            {
                "username": user.username,
                "user_id": user.user_id,
                "two_factor_auth": "active",
                "identity_verified": True
            },
            "secret",
            algorithm="HS256"
        )
        return jsonify({
            'jwt': encoded_jwt,
            'redirect_url': '/document/sign'
        })
    except ValueError as e:
        return ErrorResponse(401, "2 Factor Authentication failed").to_dict(), 401

import codecs
import json

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import render_template, request, flash, jsonify, redirect, url_for

from exceptions.error_response import ErrorResponse
from models.user import User
import jwt
import bcrypt
import uuid

ca_cert = '''-----BEGIN CERTIFICATE-----
MIIC8TCCAdmgAwIBAgIUNRcif0nNeAQkC75yGTqJofMsdgIwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPTGljZW50YSBFVFRJIENBMB4XDTIyMDYxODA5NTk1N1oX
DTI0MDkyMTA5NTk1N1owGjEYMBYGA1UEAwwPTGljZW50YSBFVFRJIENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZnhkPhDk8dLlYifpibTD1vcMWbk
8DdFcpE/7deZ78q9QqCBqigi/5Evkv0Xxo7Y+awGlybPWJuwope/Xvh4OZXwhcDL
vFcWGhflyMIKpwhfMxy7s3oXS0TA2S80pZh6zEBzVuswouoYUOnkhtkDwCk47Tiy
Pa+AMlKdVRqQ0yFsTAH156IRCUWb1ySGwvd6i4vI+BGeInLkDgHxTbhz3rZQQ6HR
993RFplE1KJdQyW7w7lhSHSwCBDi4Nyyftow/nmbw4IV8ZSw+NwNCAZeEC6wj0U9
CMeIEFY2M4VGcNPYrLRmClXlZUOfZquaz6/56kuQuKqi+NRity+sylbvHQIDAQAB
oy8wLTAaBgNVHREEEzARgg9MaWNlbnRhIEVUVEkgQ0EwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAL0++fbRXRrRfDVBAYt1zQnkQHhR/e+BVBK9P
d9Zs+3hEv/n/suTWf3/glNeyhfBl3hg/6cvRYdgcAZr/6oi4MuAQR0bKbiLJJerP
LfeWPLfM2ZkPX1SnBWKlfFrNsCN5yZlD4B/H8BUlMvfuKrDU9AZRY8Quj1goM2e4
QplI8jpSm7adwPlULJF05VY3EZyIKaf/mqq3rQAxUKOMVTEMqLIovOfpwM7aFAzX
Hk+7q7KO2urehuY3+eI/cXjE/0LBeFlOZ2OtiQG0WGZVjynjkiRFUyT9u5ZHLPAu
kOFxr/JHUIopzfrehjUN1+a6aziJAtVWvW4hfWybZkZqxn73IA==
-----END CERTIFICATE-----'''

def index():
    return render_template('register.html')

def register():
    username = request.json.get("username")
    password = str(request.json.get("password")).encode()
    twofa_option = request.json.get('2fa_option')

    user = User.objects(username=username)
    if len(user) != 0:
        flash("Username already exists.")
        return redirect('/register')

    salt = bcrypt.gensalt(10)
    hashed_password = bcrypt.hashpw(password, salt)
    user = User(user_id=str(uuid.uuid4()), username=username, hashed_password=hashed_password, active_two_fa_option=twofa_option)
    user.save()
    encoded_jwt = jwt.encode({"username": user.username, "user_id": user.user_id, "two_factor_auth": "inactive"}, "secret", algorithm="HS256")
    return jsonify({
        'jwt': encoded_jwt,
        'redirect_url': '/register/register-usb-token'
    })


def serve_register_usb_token():
    return render_template('register_usb_token.html')


def register_usb_token():
    json_web_token = request.json.get('jwt')
    decoded_jwt = jwt.decode(json_web_token, "secret", algorithms=["HS256"])
    certificate = request.json.get("certificate").replace('\r', '')
    cert_to_check = x509.load_pem_x509_certificate(bytes(certificate, 'utf-8'))
    ca_certificate = x509.load_pem_x509_certificate(bytes(ca_cert, 'utf-8'))
    public_key_pem = ca_certificate.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    issuer_public_key = load_pem_public_key(public_key_pem)
    try:
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
    except InvalidSignature as e:
        return ErrorResponse(400, "Your certificate is not valid").to_dict(), 400

    user_id = decoded_jwt.get("user_id")
    user = User.objects(user_id=user_id)
    user.update(certificate=certificate)
    encoded_jwt = jwt.encode({"username": user.first().username, "user_id": user_id, "two_factor_auth": "active"}, "secret", algorithm="HS256")
    return jsonify({
        'jwt': encoded_jwt,
        'redirect_url': '/document/sign'
    })
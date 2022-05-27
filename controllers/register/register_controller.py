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
MIIC8TCCAdmgAwIBAgIUVq9mYZWawOoVd4+hL508nU4LWkYwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPTGljZW50YSBFVFRJIENBMB4XDTIyMDUwMzAxMDUxNFoX
DTI0MDgwNjAxMDUxNFowGjEYMBYGA1UEAwwPTGljZW50YSBFVFRJIENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPciw5OuJvbGzlfrYI7ToncI/j//
C3ZrCG2+bUdtTgTaoNKQqOGdZOqtvlwa/iRwJ3iOgLi42jrOmqSihgYvNJv4OJYN
wGGBHOLnxboSm4CXE/cj1fDmA3nEhlZghf3D8wLO9ihx4eRhxB45CfzG4gEeKpTS
BWc6/uOKXGUCKr9anWhlCequxzJ/oljZSurSi3MvglN7daveZyNUlORFoLOKKGGY
CUKHmC/m0XmcZJLNj9GLCWK6yPrxFk95b6Npx/Cvq8zzpsiK1C8TOih4MLG5a9lG
Y43ZbastarrGzwbs7qgigeKpOgLhh3kCH3Iu0PvU/nqDE2YWlzO7/K5+QwIDAQAB
oy8wLTAaBgNVHREEEzARgg9MaWNlbnRhIEVUVEkgQ0EwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEApW24nurPCOXb2yF+SMsJgAXx3F3ZWWOKXVWy
H0QjSLwZPeunVWoJnvL6qR+PxgKR3/Sr37r5DUv7lnzYQNQsfnjpDxnT3xL6ZCNF
ZVThuQn187KlxY7T1YsCcPFkf4H4hCIrybqvut9npnaM0uh6FCztLKxK7Nr4CI87
PnmWylf7oga7nP479IFSkebymL2dJ/5vQgt6jA2GAdU11+06AiyMZASIu+Wf1Gos
kjiRaxj5G80bqIejfKH+M8J/BWB9yXNV/k2pitZE00x1tBzxJbBjpVliiWFvHuKN
RKyL947T+zz5NkJslA3vbH/CCIgCaMgFtLRjvBv68cA23RlpnQ==
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
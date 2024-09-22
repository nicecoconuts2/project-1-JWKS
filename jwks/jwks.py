from flask import jsonify
from .key_manager import get_valid_keys

def jwks():
    jwks_keys = []
    for kid, (public_key, expiration_time) in get_valid_keys().items():
        jwks_keys.append({
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, byteorder='big')).decode('utf-8').rstrip("=")
        })
    return jsonify(keys=jwks_keys)

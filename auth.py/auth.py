from flask import request, jsonify
from jwks.key_manager import generate_rsa_key, keys
import jwt
from datetime import datetime, timedelta

def authenticate():
    expired = request.args.get('expired')
    if expired and keys:
        expired_keys = [kid for kid, (_, _, expiration_time) in keys.items() if datetime.utcnow() >= expiration_time]
        if expired_keys:
            key_id = expired_keys[0]
        else:
            return jsonify({"error": "No expired keys available"}), 404
    else:
        key_id = generate_rsa_key()

    private_key = keys[key_id][1]
    expiration_time = keys[key_id][2] if not expired else datetime.utcnow() - timedelta(days=1)
    payload = {'username': 'fakeuser', 'exp': expiration_time}
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify(token=token)

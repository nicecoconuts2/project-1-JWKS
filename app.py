from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import base64

app = Flask(__name__)

# Dictionary to store RSA keys with their expiration time
keys = {}

# Generate RSA key pair and store it with an expiration time
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    key_id = str(len(keys) + 1)
    expiration_time = datetime.utcnow() + timedelta(days=30)  # Expiry in 30 days
    keys[key_id] = (public_key, private_key, expiration_time)
    return key_id

# Encode a number to base64url
def base64url_encode(number):
    return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    for kid, (public_key, _, expiration_time) in keys.items():
        jwks_keys.append({
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": base64url_encode(public_key.public_numbers().n),
            "e": base64url_encode(public_key.public_numbers().e)
        })

    return jsonify(keys=jwks_keys), 200

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')
    if expired:
        key_id = list(keys.keys())[0]  # Choose the first key for expired token
        expiration_time = datetime.utcnow() - timedelta(days=1)  # Set an expired time
    else:
        key_id = generate_rsa_key()
        expiration_time = keys[key_id][2]

    private_key = keys[key_id][1]
    payload = {'username': 'fakeuser', 'exp': expiration_time.timestamp()}  # Use timestamp for exp
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify(token=token)

# Token verification endpoint
@app.route('/verify', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    kid = request.json.get('kid')

    # Get the public key from the JWKS
    public_key = None
    for key_id, (pub_key, _, _) in keys.items():
        if key_id == kid:
            public_key = pub_key
            break

    if public_key:
        try:
            payload = jwt.decode(token, public_key, algorithms=['RS256'])
            return jsonify(payload=payload), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401
    else:
        return jsonify({"error": "Key ID not found."}), 404

if __name__ == '__main__':
    app.run(port=8080)

from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt

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

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    for kid, (public_key, _, expiration_time) in keys.items():
        if datetime.utcnow() < expiration_time:
            jwks_keys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": str(public_key.public_numbers().n),  # Convert n to string for JSON
                "e": str(public_key.public_numbers().e)   # Convert e to string for JSON
            })

    return jsonify(keys=jwks_keys), 200 if jwks_keys else (404, {"error": "No valid keys found."})

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')

    if expired:
        # Use the first key for expired token
        if keys:
            key_id = list(keys.keys())[0]
            expiration_time = datetime.utcnow() - timedelta(days=1)  # Set an expired time
        else:
            return jsonify({"error": "No keys available for expired token."}), 400
    else:
        key_id = generate_rsa_key()
        expiration_time = keys[key_id][2]

    private_key = keys[key_id][1]
    payload = {'username': 'fakeuser', 'exp': expiration_time}
    
    # Encode the JWT with the appropriate key ID
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify(token=token)

if __name__ == '__main__':
    app.run(port=8080)

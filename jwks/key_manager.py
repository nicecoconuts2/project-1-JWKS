from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

keys = {}

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    key_id = str(len(keys) + 1)
    expiration_time = datetime.utcnow() + timedelta(days=30)
    keys[key_id] = (public_key, private_key, expiration_time)
    return key_id

def get_valid_keys():
    return {kid: (public_key, expiration_time) for kid, (public_key, _, expiration_time) in keys.items()
            if datetime.utcnow() < expiration_time}

import pytest
from app import app  # Adjust if your main file is named differently

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert isinstance(data['keys'], list)

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data

    # Check if the token can be decoded
    token = data['token']
    assert token is not None

def test_auth_with_expired_key(client):
    # Request a token with an expired key
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data

    # Check if the token can be decoded
    token = data['token']
    assert token is not None

def test_verify_token(client):
    # First, get a token
    auth_response = client.post('/auth')
    assert auth_response.status_code == 200
    token = auth_response.get_json()['token']

    # Verify the token
    verify_response = client.post('/verify', json={'token': token, 'kid': '1'})
    assert verify_response.status_code == 200
    assert 'username' in verify_response.get_json()['payload']

def test_verify_invalid_token(client):
    # Verify a non-existent token
    verify_response = client.post('/verify', json={'token': 'invalid_token', 'kid': '1'})
    assert verify_response.status_code == 401
    assert verify_response.get_json() == {"error": "Invalid token."}

def test_verify_expired_token(client):
    # Get an expired token
    auth_response = client.post('/auth?expired=true')
    assert auth_response.status_code == 200
    expired_token = auth_response.get_json()['token']

    # Attempt to verify the expired token
    verify_response = client.post('/verify', json={'token': expired_token, 'kid': '1'})
    assert verify_response.status_code == 401
    assert verify_response.get_json() == {"error": "Token has expired."}

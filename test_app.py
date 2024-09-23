import pytest
from app import app  # Adjust this import if your main file is named differently

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert 'keys' in response.get_json()
    assert len(response.get_json()['keys']) > 0  # Check that there are keys returned

def test_auth_valid_token(client):
    response = client.post('/auth', json={'expired': False})
    assert response.status_code == 200
    assert 'token' in response.get_json()

def test_auth_expired_token(client):
    response = client.post('/auth', json={'expired': True})
    assert response.status_code == 200
    assert 'token' in response.get_json()

def test_verify_token(client):
    # Obtain a valid token first
    auth_response = client.post('/auth', json={'expired': False})
    token = auth_response.get_json()['token']
    
    # Verify the valid token
    response = client.post('/verify', json={'token': token, 'kid': '1'})  # Adjust 'kid' as necessary
    assert response.status_code == 200
    assert 'payload' in response.get_json()

def test_verify_invalid_token(client):
    invalid_token = "invalid.token.here"
    response = client.post('/verify', json={'token': invalid_token, 'kid': '1'})
    assert response.status_code == 401
    assert 'error' in response.get_json()

def test_verify_expired_token(client):
    expired_response = client.post('/auth', json={'expired': True})
    expired_token = expired_response.get_json()['token']
    response = client.post('/verify', json={'token': expired_token, 'kid': '1'})
    assert response.status_code == 401
    assert 'error' in response.get_json()

def test_verify_missing_kid(client):
    auth_response = client.post('/auth', json={'expired': False})
    token = auth_response.get_json()['token']
    
    # Attempt to verify with a missing kid
    response = client.post('/verify', json={'token': token})
    assert response.status_code == 400  # Expecting a bad request due to missing 'kid'

def test_verify_invalid_kid(client):
    auth_response = client.post('/auth', json={'expired': False})
    token = auth_response.get_json()['token']
    
    response = client.post('/verify', json={'token': token, 'kid': 'invalid_id'})
    assert response.status_code == 404  # Key ID not found

def test_generate_rsa_key(client):
    # Test the key generation directly
    key_id = client.application.generate_rsa_key()
    assert key_id in client.application.keys
    assert len(client.application.keys) == 1  # Check that a key has been added

def test_jwks_empty_keys(client):
    # Simulate no keys and test the response
    client.application.keys.clear()
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert response.get_json() == {'keys': []}

if __name__ == "__main__":
    pytest.main()

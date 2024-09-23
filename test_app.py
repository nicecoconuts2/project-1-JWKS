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

if __name__ == "__main__":
    pytest.main()

import pytest
from app import app  # Adjust this import if your main file is named differently

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_jwks(client):
    # Test JWKS endpoint returns keys
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert isinstance(data['keys'], list)

def test_jwks_no_expired_keys(client):
    # Test JWKS with valid keys
    client.post('/auth')  # Generate a key
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['keys']) > 0  # Check that keys are returned

def test_auth_valid(client):
    # Test successful JWT issuance
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    assert isinstance(data['token'], str)

def test_auth_expired(client):
    # Test JWT issuance with expired key
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    assert isinstance(data['token'], str)

def test_verify_token_valid(client):
    # First authenticate to get a valid token
    auth_response = client.post('/auth')
    token = auth_response.get_json()['token']
    
    response = client.post('/verify', json={'token': token, 'kid': '1'})  # Use the correct kid
    assert response.status_code == 200
    payload = response.get_json()
    assert 'username' in payload
    assert payload['username'] == 'fakeuser'

def test_verify_token_invalid(client):
    # Test verification of an invalid token
    response = client.post('/verify', json={'token': 'invalid_token', 'kid': '1'})
    assert response.status_code == 401
    assert 'error' in response.get_json()

def test_verify_token_expired(client):
    # First authenticate to get an expired token
    auth_response = client.post('/auth?expired=true')
    token = auth_response.get_json()['token']

    response = client.post('/verify', json={'token': token, 'kid': '1'})  # Use the correct kid
    assert response.status_code == 401
    assert response.get_json()['error'] == "Token has expired."

def test_jwks_key_expiry(client):
    # Test JWKS when keys are expired
    auth_response = client.post('/auth?expired=true')
    token = auth_response.get_json()['token']
    # Simulate key expiry by directly manipulating the keys dictionary
    app.keys.clear()  # Clear keys to simulate expired keys

    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert data['keys'] == []  # Expect no keys to be returned

if __name__ == '__main__':
    pytest.main()

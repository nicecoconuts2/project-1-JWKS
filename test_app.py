import pytest
from app import app  # Ensure this matches your main application filename

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

def test_verify_token(client):
    auth_response = client.post('/auth')
    token = auth_response.get_json()['token']
    verify_response = client.post('/verify', json={'token': token, 'kid': '1'})
    assert verify_response.status_code == 200

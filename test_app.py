import pytest
from app import app  # Adjust this import if your main file is named differently

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')  # Updated endpoint
    assert response.status_code == 200
    assert 'keys' in response.get_json()

def test_auth(client):
    response = client.post('/auth', json={'expired': False})  # Specify JSON data
    assert response.status_code == 200
    assert 'token' in response.get_json()

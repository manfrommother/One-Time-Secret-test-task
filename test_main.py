from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_generate_secret():
    response = client.post(
        "/generate",
        json={"secret": "test secret", "passphrase": "test passphrase", "ttl": 3600}
    )
    assert response.status_code == 200
    assert "secret_key" in response.json()

def test_retrieve_secret():
    # First, generate a secret
    generate_response = client.post(
        "/generate",
        json={"secret": "test secret", "passphrase": "test passphrase", "ttl": 3600}
    )
    secret_key = generate_response.json()["secret_key"]

    # Then, retrieve the secret
    retrieve_response = client.post(
        f"/secrets/{secret_key}",
        json={"passphrase": "test passphrase"}
    )
    assert retrieve_response.status_code == 200
    assert retrieve_response.json() == "test secret"

    # Try to retrieve the secret again (should fail)
    second_retrieve_response = client.post(
        f"/secrets/{secret_key}",
        json={"passphrase": "test passphrase"}
    )
    assert second_retrieve_response.status_code == 404

def test_retrieve_secret_wrong_passphrase():
    # Generate a secret
    generate_response = client.post(
        "/generate",
        json={"secret": "test secret", "passphrase": "correct passphrase", "ttl": 3600}
    )
    secret_key = generate_response.json()["secret_key"]

    # Try to retrieve with wrong passphrase
    retrieve_response = client.post(
        f"/secrets/{secret_key}",
        json={"passphrase": "wrong passphrase"}
    )
    assert retrieve_response.status_code == 403



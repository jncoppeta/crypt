from fastapi.testclient import TestClient
from main import app  # Import your FastAPI app from your main file
import os
from dotenv import load_dotenv


load_dotenv()
TOKEN = os.getenv("CRYPT_TOKEN")
USER_ID = os.getenv("USER_ID")
client = TestClient(app)

def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"message": "Healthy"}

def test_get_users():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    response = client.get("/api/v1/users", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"users": ["coppetaj"]}

def test_get_users_id():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    response = client.get(f"/api/v1/users/{USER_ID}", headers=headers)
    assert response.status_code == 200
    assert response.json() == {'id': USER_ID, 'username': 'coppetaj'}
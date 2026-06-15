import json
import pytest
import models


def test_register_and_login(client, app):
    """Test user registration and subsequent login flow."""
    # 1. Register new user in a new tenant
    reg_payload = {
        "name": "Acme CEO",
        "email": "ceo@acme-corp.com",
        "password": "Password@123",
        "confirm_password": "Password@123",
        "role": "admin",
        "tenant_name": "Acme Corp Ltd"
    }
    
    reg_response = client.post(
        '/api/auth/register',
        data=json.dumps(reg_payload),
        content_type='application/json'
    )
    
    assert reg_response.status_code == 201
    reg_data = json.loads(reg_response.data)
    assert reg_data['success'] is True
    assert 'token' in reg_data
    assert reg_data['user']['email'] == "ceo@acme-corp.com"
    assert reg_data['user']['tenant_name'] == "Acme Corp Ltd"
    
    # Verify tenant was created in DB
    with app.app_context():
        tenant = models.get_tenant_by_name("Acme Corp Ltd")
        assert tenant is not None
        assert tenant['id'] == reg_data['user']['tenant_id']

    # 2. Test Login with registered credentials
    login_payload = {
        "email": "ceo@acme-corp.com",
        "password": "Password@123"
    }
    
    login_response = client.post(
        '/api/auth/login',
        data=json.dumps(login_payload),
        content_type='application/json'
    )
    
    assert login_response.status_code == 200
    login_data = json.loads(login_response.data)
    assert login_data['success'] is True
    assert 'token' in login_data
    assert login_data['user']['name'] == "Acme CEO"


def test_login_invalid_credentials(client):
    """Test login fails with invalid credentials."""
    login_payload = {
        "email": "nonexistent@cyberguard.ai",
        "password": "WrongPassword"
    }
    
    response = client.post(
        '/api/auth/login',
        data=json.dumps(login_payload),
        content_type='application/json'
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['success'] is False
    assert data['error'] == "Invalid credentials"

import json
import pytest
import jwt
from config import Config
import models


def _get_auth_headers(client, email, password):
    """Helper to login and get bearer authorization headers."""
    payload = {"email": email, "password": password}
    response = client.post(
        '/api/auth/login',
        data=json.dumps(payload),
        content_type='application/json'
    )
    data = json.loads(response.data)
    return {'Authorization': f"Bearer {data['token']}"}


def test_scanner_rbac_restrictions(client):
    """Verify that User role cannot start scans but Analyst/Admin can."""
    # 1. Login as standard user
    user_headers = _get_auth_headers(client, "user@cyberguard.ai", "User@123")
    
    # Try initiating scan as standard user (Should be Blocked)
    scan_payload = {"url": "https://threat-target.org"}
    user_response = client.post(
        '/api/scans',
        headers=user_headers,
        data=json.dumps(scan_payload),
        content_type='application/json'
    )
    assert user_response.status_code == 403
    user_data = json.loads(user_response.data)
    assert "insufficient permissions" in user_data['error']

    # 2. Login as Analyst (Should be Allowed)
    analyst_headers = _get_auth_headers(client, "analyst@cyberguard.ai", "Analyst@123")
    analyst_response = client.post(
        '/api/scans',
        headers=analyst_headers,
        data=json.dumps(scan_payload),
        content_type='application/json'
    )
    assert analyst_response.status_code == 201
    analyst_data = json.loads(analyst_response.data)
    assert analyst_data['success'] is True
    assert analyst_data['scan']['target_url'] == "https://threat-target.org"


def test_scanner_multi_tenant_isolation(client, app):
    """Verify Tenant A users cannot access Tenant B scans."""
    # Seed a scan for Tenant 2 manually
    with app.app_context():
        # User ID 4 belongs to Tenant 2 (Acme Corp)
        acme_user = models.get_user_by_id(4)
        assert acme_user['tenant_id'] == 2
        
        # Create scan under Tenant 2
        tenant_2_scan_id = models.create_scan(
            tenant_id=2,
            user_id=4,
            target_url="https://acme-internal.com",
            port_results="[]",
            ssl_results="{}",
            header_results="[]",
            directory_results="[]",
            started_at="2026-06-14 10:00:00",
            completed_at="2026-06-14 10:01:00"
        )
        assert tenant_2_scan_id is not None

    # Login as Tenant 1 Admin (admin@cyberguard.ai)
    t1_headers = _get_auth_headers(client, "admin@cyberguard.ai", "Admin@123")
    
    # Try accessing Tenant 2 scan using Tenant 1 token (Should fail with 404/403)
    t1_response = client.get(
        f'/api/scans/{tenant_2_scan_id}',
        headers=t1_headers
    )
    assert t1_response.status_code == 404
    t1_data = json.loads(t1_response.data)
    assert "Scan not found in your workspace" in t1_data['error']
    
    # Login as Tenant 2 Admin (acme_admin@cyberguard.ai)
    t2_headers = _get_auth_headers(client, "acme_admin@cyberguard.ai", "Admin@123")
    
    # Access Tenant 2 scan using Tenant 2 token (Should succeed)
    t2_response = client.get(
        f'/api/scans/{tenant_2_scan_id}',
        headers=t2_headers
    )
    assert t2_response.status_code == 200
    t2_data = json.loads(t2_response.data)
    assert t2_data['success'] is True
    assert t2_data['scan']['target_url'] == "https://acme-internal.com"

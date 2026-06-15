import json
import pytest


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


def test_siem_endpoints(client):
    """Verify SIEM retrieval, filtering, and RBAC controls."""
    # 1. Login as standard user (Should be blocked)
    user_headers = _get_auth_headers(client, "user@cyberguard.ai", "User@123")
    user_response = client.get('/api/siem', headers=user_headers)
    assert user_response.status_code == 403
    user_data = json.loads(user_response.data)
    assert "insufficient permissions" in user_data['error']

    # 2. Login as Analyst (Should be allowed)
    analyst_headers = _get_auth_headers(client, "analyst@cyberguard.ai", "Analyst@123")
    analyst_response = client.get('/api/siem', headers=analyst_headers)
    assert analyst_response.status_code == 200
    analyst_data = json.loads(analyst_response.data)
    assert analyst_data['success'] is True
    # We seeded 4 events for tenant 1
    assert len(analyst_data['events']) == 4

    # 3. Test filtering SIEM events by severity
    critical_response = client.get('/api/siem?severity=Critical', headers=analyst_headers)
    assert critical_response.status_code == 200
    critical_data = json.loads(critical_response.data)
    # We seeded 2 critical events: privilege_escalation and data_exfiltration
    assert len(critical_data['events']) == 2
    for event in critical_data['events']:
        assert event['severity'] == "Critical"

    # 4. Test filtering SIEM events by search query
    search_response = client.get('/api/siem?q=login', headers=analyst_headers)
    assert search_response.status_code == 200
    search_data = json.loads(search_response.data)
    assert len(search_data['events']) == 1
    assert "failed login attempts" in search_data['events'][0]['description']

# CyberGuard AI — REST API Documentation

## Base URL

```
http://localhost:5000
```

## Authentication

All protected endpoints require a JWT token in the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

Tokens are obtained via the `/api/auth/login` or `/api/auth/register` endpoints and expire after 24 hours.

---

## Endpoints

### Authentication

#### POST `/api/auth/register`

Create a new user account.

**Request Body:**
```json
{
    "name": "Jane Analyst",
    "email": "jane@example.com",
    "password": "SecurePass123",
    "confirm_password": "SecurePass123",
    "role": "analyst"
}
```

| Field              | Type   | Required | Notes                          |
|--------------------|--------|----------|--------------------------------|
| name               | string | Yes      | Full name                      |
| email              | string | Yes      | Valid email, must be unique     |
| password           | string | Yes      | Minimum 8 characters           |
| confirm_password   | string | Yes      | Must match password            |
| role               | string | No       | `analyst` (default) or `admin` |

**Response 201:**
```json
{
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
        "id": 3,
        "name": "Jane Analyst",
        "email": "jane@example.com",
        "role": "analyst",
        "status": "active",
        "created_at": "2026-06-14 10:30:00"
    }
}
```

**Errors:**
- `400` — Validation error (missing fields, email taken, passwords don't match)

---

#### POST `/api/auth/login`

Authenticate and receive a JWT token.

**Request Body:**
```json
{
    "email": "admin@cyberguard.ai",
    "password": "Admin@123"
}
```

**Response 200:**
```json
{
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
        "id": 1,
        "name": "Admin User",
        "email": "admin@cyberguard.ai",
        "role": "admin",
        "status": "active",
        "created_at": "2026-06-14 10:00:00"
    }
}
```

**Errors:**
- `401` — Invalid credentials
- `423` — Account locked (too many failed attempts)

---

#### GET `/api/auth/me`

Get the current authenticated user's profile.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "user": {
        "id": 1,
        "name": "Admin User",
        "email": "admin@cyberguard.ai",
        "role": "admin",
        "status": "active",
        "created_at": "2026-06-14 10:00:00"
    }
}
```

---

### Scans

#### POST `/api/scans`

Initiate a new vulnerability scan (simulated).

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
    "url": "https://example.com"
}
```

**Response 201:**
```json
{
    "success": true,
    "scan": {
        "id": 1,
        "target_url": "https://example.com",
        "status": "completed",
        "port_results": [
            {"port": 80, "service": "HTTP", "version": "Apache/2.4.52", "state": "open"},
            {"port": 443, "service": "HTTPS", "version": "nginx/1.24.0", "state": "open"}
        ],
        "ssl_results": {
            "valid": true,
            "issuer": "Let's Encrypt",
            "expiry": "2026-12-01",
            "cipher_strength": "strong",
            "grade": "A",
            "protocol": "TLSv1.3",
            "key_size": 2048
        },
        "header_results": [
            {"header": "X-Frame-Options", "present": true, "value": "DENY", "status": "pass", "recommendation": "Properly configured."}
        ],
        "directory_results": [
            {"path": "/admin", "status": 403, "found": true, "risk": "medium"}
        ],
        "vulnerabilities": [
            {
                "id": 1,
                "owasp_category": "A05:2021",
                "title": "Security Misconfiguration - Missing CSP Header",
                "description": "Content-Security-Policy header is not set...",
                "severity": "Medium",
                "affected_endpoint": "/",
                "remediation": "Add a Content-Security-Policy header...",
                "cwe_id": "CWE-693",
                "cvss_score": 5.3
            }
        ],
        "risk_score": {
            "risk_score": 45.2,
            "severity_level": "High",
            "grade": "C",
            "contributing_factors": [...],
            "ai_explanation": "The target website presents a HIGH risk level..."
        },
        "threat_intel": {
            "domain": "example.com",
            "status": "Safe",
            "risk_score": 12
        },
        "started_at": "2026-06-14 10:30:00",
        "completed_at": "2026-06-14 10:30:05"
    }
}
```

**Errors:**
- `400` — Invalid URL format

---

#### GET `/api/scans`

List all scans for the current user (or all scans for admins).

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "scans": [
        {
            "id": 1,
            "target_url": "https://example.com",
            "status": "completed",
            "vulnerability_count": 7,
            "risk_score": 45.2,
            "grade": "C",
            "created_at": "2026-06-14 10:30:00"
        }
    ]
}
```

---

#### GET `/api/scans/:id`

Get detailed results for a specific scan.

**Headers:** `Authorization: Bearer <token>`

**Response 200:** Same structure as POST `/api/scans` response.

**Errors:**
- `403` — Not scan owner (analysts)
- `404` — Scan not found

---

#### DELETE `/api/scans/:id`

Delete a scan and its associated data.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "message": "Scan deleted successfully"
}
```

---

### Dashboard

#### GET `/api/dashboard/stats`

Get dashboard KPI statistics.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "stats": {
        "total_scans": 15,
        "total_vulnerabilities": 47,
        "critical_count": 8,
        "avg_risk_score": 52.3,
        "scans_this_month": 5,
        "most_common_vuln": "A05:2021"
    }
}
```

---

#### GET `/api/dashboard/charts`

Get aggregated chart data.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "charts": {
        "vuln_distribution": {
            "labels": ["A01:2021", "A02:2021", "A03:2021", "A05:2021", "A07:2021"],
            "data": [5, 3, 8, 12, 4]
        },
        "severity_breakdown": {
            "labels": ["Critical", "High", "Medium", "Low"],
            "data": [8, 15, 18, 6]
        },
        "risk_trend": {
            "labels": ["2026-06-01", "2026-06-05", "2026-06-10", "2026-06-14"],
            "data": [65.2, 52.1, 48.5, 45.2]
        },
        "monthly_scans": {
            "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
            "data": [2, 4, 3, 5, 7, 5]
        }
    }
}
```

---

#### GET `/api/dashboard/recent`

Get recent scan activity.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "recent": [
        {
            "id": 5,
            "target_url": "https://example.com",
            "risk_score": 45.2,
            "vulnerability_count": 7,
            "grade": "C",
            "created_at": "2026-06-14 10:30:00"
        }
    ]
}
```

---

### Threat Intelligence

#### GET `/api/threat-intel/cves`

Get the latest CVE entries (mocked data).

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Param    | Type    | Default | Description          |
|----------|---------|---------|----------------------|
| limit    | integer | 20      | Max results          |
| severity | string  | —       | Filter by severity   |

**Response 200:**
```json
{
    "success": true,
    "cves": [
        {
            "cve_id": "CVE-2024-21762",
            "title": "Fortinet FortiOS Out-of-Bound Write",
            "description": "An out-of-bounds write vulnerability in FortiOS...",
            "severity": "Critical",
            "cvss_score": 9.8,
            "published_date": "2024-02-08",
            "affected_products": ["FortiOS 7.4.0-7.4.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"]
        }
    ]
}
```

---

#### GET `/api/threat-intel/domain/:domain`

Check domain reputation (mocked).

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "reputation": {
        "domain": "example.com",
        "status": "Safe",
        "risk_score": 12,
        "blacklisted": false,
        "last_analysis": "2026-06-14",
        "details": {
            "malware": false,
            "phishing": false,
            "spam": false,
            "reputation_score": 88
        },
        "whois": {
            "registrar": "Example Registrar",
            "creation_date": "1995-08-14",
            "country": "US"
        }
    }
}
```

---

#### GET `/api/threat-intel/global-status`

Get global threat level overview.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "global": {
        "threat_level": "Elevated",
        "active_threats": 1247,
        "recent_cves_count": 89,
        "last_updated": "2026-06-14 10:00:00",
        "top_threat_categories": [
            {"category": "Ransomware", "count": 342},
            {"category": "Zero-Day Exploits", "count": 23}
        ]
    }
}
```

---

### Reports

#### POST `/api/reports/generate/:scan_id`

Generate a PDF report for a completed scan.

**Headers:** `Authorization: Bearer <token>`

**Response 201:**
```json
{
    "success": true,
    "report": {
        "id": 1,
        "scan_id": 5,
        "filename": "CyberGuard_Report_5_20260614_103000.pdf",
        "created_at": "2026-06-14 10:30:05"
    }
}
```

---

#### GET `/api/reports`

List all reports for the current user.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
    "success": true,
    "reports": [
        {
            "id": 1,
            "scan_id": 5,
            "target_url": "https://example.com",
            "filename": "CyberGuard_Report_5_20260614_103000.pdf",
            "created_at": "2026-06-14 10:30:05"
        }
    ]
}
```

---

#### GET `/api/reports/:id/download`

Download a generated PDF report.

**Headers:** `Authorization: Bearer <token>`

**Response 200:** Binary PDF file with `Content-Type: application/pdf`

---

### Admin

> All admin endpoints require `role: admin` in the JWT token.

#### GET `/api/admin/users`

List all platform users.

**Response 200:**
```json
{
    "success": true,
    "users": [
        {
            "id": 1,
            "name": "Admin User",
            "email": "admin@cyberguard.ai",
            "role": "admin",
            "status": "active",
            "created_at": "2026-06-14 10:00:00",
            "scan_count": 3
        }
    ]
}
```

---

#### PUT `/api/admin/users/:id`

Update a user's status or role.

**Request Body:**
```json
{
    "status": "suspended",
    "role": "analyst"
}
```

**Response 200:**
```json
{
    "success": true,
    "user": {
        "id": 2,
        "name": "John Analyst",
        "email": "analyst@cyberguard.ai",
        "role": "analyst",
        "status": "suspended"
    }
}
```

---

#### DELETE `/api/admin/users/:id`

Delete a user account. Cannot delete your own account.

**Response 200:**
```json
{
    "success": true,
    "message": "User deleted successfully"
}
```

---

#### GET `/api/admin/scans`

List all scans across the platform.

**Response 200:**
```json
{
    "success": true,
    "scans": [
        {
            "id": 1,
            "user_id": 1,
            "user_name": "Admin User",
            "user_email": "admin@cyberguard.ai",
            "target_url": "https://example.com",
            "status": "completed",
            "risk_score": 45.2,
            "vulnerability_count": 7,
            "created_at": "2026-06-14 10:30:00"
        }
    ]
}
```

---

#### GET `/api/admin/audit-logs`

View system audit logs.

**Query Parameters:**
| Param  | Type    | Default | Description            |
|--------|---------|---------|------------------------|
| limit  | integer | 50      | Max results            |
| action | string  | —       | Filter by action type  |

**Response 200:**
```json
{
    "success": true,
    "logs": [
        {
            "id": 1,
            "user_id": 1,
            "user_email": "admin@cyberguard.ai",
            "action": "LOGIN",
            "details": "Successful login",
            "ip_address": "127.0.0.1",
            "created_at": "2026-06-14 10:00:00"
        }
    ]
}
```

---

#### GET `/api/admin/stats`

Get platform-wide statistics.

**Response 200:**
```json
{
    "success": true,
    "stats": {
        "total_users": 5,
        "active_users": 4,
        "suspended_users": 1,
        "total_scans": 15,
        "total_vulnerabilities": 47,
        "total_reports": 3,
        "avg_risk_score": 52.3,
        "critical_findings": 8,
        "scans_today": 2,
        "new_users_this_month": 3
    }
}
```

---

## Error Responses

All error responses follow this format:

```json
{
    "success": false,
    "error": "Human-readable error message"
}
```

### HTTP Status Codes

| Code | Meaning                                 |
|------|-----------------------------------------|
| 200  | Success                                 |
| 201  | Created (new resource)                  |
| 400  | Bad Request (validation error)          |
| 401  | Unauthorized (invalid/missing token)    |
| 403  | Forbidden (insufficient permissions)    |
| 404  | Not Found                               |
| 423  | Locked (account locked)                 |
| 500  | Internal Server Error                   |

"""
Database module for CyberGuard AI - Threat Detection Platform.
Handles SQLite connection, schema initialization, and seed data.
"""

import sqlite3
import json
import bcrypt
import random
from datetime import datetime
from config import Config


def get_db():
    """Returns a database connection with Row factory enabled."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Creates all database tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            status TEXT NOT NULL DEFAULT 'active',
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'completed',
            scan_type TEXT DEFAULT 'full',
            port_results TEXT,
            ssl_results TEXT,
            header_results TEXT,
            directory_results TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            owasp_category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            affected_endpoint TEXT,
            remediation TEXT,
            cwe_id TEXT,
            cvss_score REAL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL UNIQUE,
            risk_score REAL NOT NULL,
            severity_level TEXT NOT NULL,
            grade TEXT NOT NULL,
            contributing_factors TEXT,
            ai_explanation TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            domain TEXT,
            reputation TEXT,
            threat_data TEXT,
            checked_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            status TEXT DEFAULT 'success',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS siem_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            epss_score REAL,
            epss_percentile REAL,
            published_date TEXT,
            affected_products TEXT,
            references_json TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)

    conn.commit()
    conn.close()


def seed_db():
    """Seeds the database with sample tenants, users, scans, vulnerabilities, risk scores, SIEM events, and CVEs."""
    conn = get_db()
    cursor = conn.cursor()

    # -------------------------------------------------------------------------
    # 1. Create Tenants
    # -------------------------------------------------------------------------
    cursor.execute("INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?, ?, ?)", (1, 'Default Org', '2026-05-01 08:00:00'))
    tenant_1_id = 1
    cursor.execute("INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?, ?, ?)", (2, 'Acme Corp', '2026-05-02 08:00:00'))
    tenant_2_id = 2

    # -------------------------------------------------------------------------
    # 2. Create Users
    # -------------------------------------------------------------------------
    admin_hash = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    analyst_hash = bcrypt.hashpw('Analyst@123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_hash = bcrypt.hashpw('User@123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Tenant 1 Users
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, tenant_id, name, email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (1, tenant_1_id, 'Admin User', 'admin@cyberguard.ai', admin_hash, 'admin', 'active', '2026-05-01 08:00:00')
    )
    admin_id = 1

    cursor.execute(
        "INSERT OR IGNORE INTO users (id, tenant_id, name, email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (2, tenant_1_id, 'John Analyst', 'analyst@cyberguard.ai', analyst_hash, 'analyst', 'active', '2026-05-10 09:30:00')
    )
    analyst_id = 2

    cursor.execute(
        "INSERT OR IGNORE INTO users (id, tenant_id, name, email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (3, tenant_1_id, 'Sarah User', 'user@cyberguard.ai', user_hash, 'user', 'active', '2026-05-12 10:00:00')
    )
    user_id = 3

    # Tenant 2 Users
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, tenant_id, name, email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (4, tenant_2_id, 'Acme Admin', 'acme_admin@cyberguard.ai', admin_hash, 'admin', 'active', '2026-05-15 08:00:00')
    )
    acme_admin_id = 4

    # -------------------------------------------------------------------------
    # 3. Create Scans (Tenant 1)
    # -------------------------------------------------------------------------
    scans_data = [
        {
            'id': 1,
            'tenant_id': tenant_1_id,
            'user_id': admin_id,
            'target_url': 'https://acme-corp.com',
            'port_results': json.dumps([
                {"port": 80, "service": "HTTP", "version": "Apache/2.4.41", "state": "open"},
                {"port": 443, "service": "HTTPS", "version": "Apache/2.4.41", "state": "open"},
                {"port": 22, "service": "SSH", "version": "OpenSSH 8.2p1", "state": "open"},
                {"port": 3306, "service": "MySQL", "version": "MySQL 8.0.28", "state": "open"},
                {"port": 8080, "service": "HTTP-Proxy", "version": "Nginx/1.21.6", "state": "open"},
                {"port": 21, "service": "FTP", "version": "vsftpd 3.0.5", "state": "open"}
            ]),
            'ssl_results': json.dumps({
                "valid": True, "issuer": "Let's Encrypt", "expiry": "2026-12-01",
                "cipher_strength": "strong", "grade": "A", "protocol": "TLSv1.3", "key_size": 2048
            }),
            'header_results': json.dumps([
                {"header": "X-Frame-Options", "present": True, "value": "DENY", "status": "pass"},
                {"header": "Content-Security-Policy", "present": False, "value": None, "status": "fail"},
                {"header": "Strict-Transport-Security", "present": True, "value": "max-age=31536000", "status": "pass"},
                {"header": "X-XSS-Protection", "present": True, "value": "1; mode=block", "status": "pass"},
                {"header": "X-Content-Type-Options", "present": True, "value": "nosniff", "status": "pass"},
                {"header": "Referrer-Policy", "present": False, "value": None, "status": "fail"},
                {"header": "Permissions-Policy", "present": False, "value": None, "status": "fail"}
            ]),
            'directory_results': json.dumps([
                {"path": "/admin", "status": 200, "found": True, "risk": "high"},
                {"path": "/login", "status": 200, "found": True, "risk": "low"},
                {"path": "/backup", "status": 403, "found": True, "risk": "medium"},
                {"path": "/.env", "status": 200, "found": True, "risk": "high"},
                {"path": "/.git", "status": 404, "found": False, "risk": "none"},
                {"path": "/api", "status": 200, "found": True, "risk": "low"}
            ]),
            'started_at': '2026-06-10 14:00:00',
            'completed_at': '2026-06-10 14:02:35',
            'created_at': '2026-06-10 14:00:00'
        },
        {
            'id': 2,
            'tenant_id': tenant_1_id,
            'user_id': admin_id,
            'target_url': 'https://secure-bank.io',
            'port_results': json.dumps([
                {"port": 80, "service": "HTTP", "version": "Nginx/1.22.1", "state": "open"},
                {"port": 443, "service": "HTTPS", "version": "Nginx/1.22.1", "state": "open"},
                {"port": 22, "service": "SSH", "version": "OpenSSH 9.1", "state": "filtered"}
            ]),
            'ssl_results': json.dumps({
                "valid": True, "issuer": "DigiCert", "expiry": "2027-03-15",
                "cipher_strength": "strong", "grade": "A+", "protocol": "TLSv1.3", "key_size": 4096
            }),
            'header_results': json.dumps([
                {"header": "X-Frame-Options", "present": True, "value": "SAMEORIGIN", "status": "pass"},
                {"header": "Content-Security-Policy", "present": True, "value": "default-src 'self'", "status": "pass"},
                {"header": "Strict-Transport-Security", "present": True, "value": "max-age=63072000; includeSubDomains; preload", "status": "pass"},
                {"header": "X-XSS-Protection", "present": True, "value": "1; mode=block", "status": "pass"},
                {"header": "X-Content-Type-Options", "present": True, "value": "nosniff", "status": "pass"},
                {"header": "Referrer-Policy", "present": True, "value": "strict-origin-when-cross-origin", "status": "pass"},
                {"header": "Permissions-Policy", "present": True, "value": "geolocation=(), camera=()", "status": "pass"}
            ]),
            'directory_results': json.dumps([
                {"path": "/admin", "status": 403, "found": True, "risk": "low"},
                {"path": "/login", "status": 200, "found": True, "risk": "low"},
                {"path": "/backup", "status": 404, "found": False, "risk": "none"},
                {"path": "/.env", "status": 404, "found": False, "risk": "none"},
                {"path": "/.git", "status": 404, "found": False, "risk": "none"},
                {"path": "/api", "status": 200, "found": True, "risk": "low"}
            ]),
            'started_at': '2026-06-11 09:00:00',
            'completed_at': '2026-06-11 09:01:45',
            'created_at': '2026-06-11 09:00:00'
        },
        {
            'id': 3,
            'tenant_id': tenant_1_id,
            'user_id': analyst_id,
            'target_url': 'https://legacy-app.example.org',
            'port_results': json.dumps([
                {"port": 80, "service": "HTTP", "version": "Apache/2.2.34", "state": "open"},
                {"port": 443, "service": "HTTPS", "version": "Apache/2.2.34", "state": "open"},
                {"port": 21, "service": "FTP", "version": "ProFTPD 1.3.5", "state": "open"},
                {"port": 22, "service": "SSH", "version": "OpenSSH 7.4", "state": "open"},
                {"port": 3306, "service": "MySQL", "version": "MySQL 5.7.42", "state": "open"},
                {"port": 5432, "service": "PostgreSQL", "version": "PostgreSQL 12.4", "state": "open"},
                {"port": 8080, "service": "HTTP-Proxy", "version": "Tomcat/9.0.65", "state": "open"},
                {"port": 8443, "service": "HTTPS-Alt", "version": "Tomcat/9.0.65", "state": "open"}
            ]),
            'ssl_results': json.dumps({
                "valid": True, "issuer": "Comodo CA", "expiry": "2026-08-15",
                "cipher_strength": "weak", "grade": "D", "protocol": "TLSv1.1", "key_size": 1024
            }),
            'header_results': json.dumps([
                {"header": "X-Frame-Options", "present": False, "value": None, "status": "fail"},
                {"header": "Content-Security-Policy", "present": False, "value": None, "status": "fail"},
                {"header": "Strict-Transport-Security", "present": False, "value": None, "status": "fail"},
                {"header": "X-XSS-Protection", "present": False, "value": None, "status": "fail"},
                {"header": "X-Content-Type-Options", "present": False, "value": None, "status": "fail"},
                {"header": "Referrer-Policy", "present": False, "value": None, "status": "fail"},
                {"header": "Permissions-Policy", "present": False, "value": None, "status": "fail"}
            ]),
            'directory_results': json.dumps([
                {"path": "/admin", "status": 200, "found": True, "risk": "high"},
                {"path": "/login", "status": 200, "found": True, "risk": "low"},
                {"path": "/backup", "status": 200, "found": True, "risk": "high"},
                {"path": "/uploads", "status": 200, "found": True, "risk": "medium"},
                {"path": "/config", "status": 200, "found": True, "risk": "high"},
                {"path": "/debug", "status": 200, "found": True, "risk": "high"},
                {"path": "/phpinfo", "status": 200, "found": True, "risk": "high"},
                {"path": "/.env", "status": 200, "found": True, "risk": "high"},
                {"path": "/.git", "status": 200, "found": True, "risk": "high"},
                {"path": "/api", "status": 200, "found": True, "risk": "low"}
            ]),
            'started_at': '2026-06-12 10:30:00',
            'completed_at': '2026-06-12 10:34:10',
            'created_at': '2026-06-12 10:30:00'
        }
    ]

    for scan in scans_data:
        cursor.execute(
            """INSERT OR IGNORE INTO scans (id, tenant_id, user_id, target_url, status, scan_type, port_results, ssl_results,
               header_results, directory_results, started_at, completed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan['id'], scan['tenant_id'], scan['user_id'], scan['target_url'], 'completed', 'full', scan['port_results'], scan['ssl_results'],
             scan['header_results'], scan['directory_results'], scan['started_at'],
             scan['completed_at'], scan['created_at'])
        )

    # -------------------------------------------------------------------------
    # 4. Create Vulnerabilities (Tenant 1)
    # -------------------------------------------------------------------------
    vulnerabilities_data = [
        # Scan 1: acme-corp.com
        (1, 'A05:2021', 'Missing Content-Security-Policy Header',
         'The Content-Security-Policy (CSP) header is not configured on the target application. Without CSP, the application is vulnerable to cross-site scripting (XSS) attacks, clickjacking through inline frames, and unauthorized code execution via injected scripts.',
         'High', 'https://acme-corp.com', 'Implement a strict Content-Security-Policy header.', 'CWE-693', 7.5),
        (1, 'A01:2021', 'Admin Panel Publicly Accessible',
         'The administrative panel at /admin is directly accessible without IP-based restrictions or VPN requirements.',
         'Critical', '/admin', 'Restrict access to the admin panel using IP whitelisting or VPN.', 'CWE-284', 9.1),
        (1, 'A02:2021', 'Environment File Exposed',
         'The .env file containing application secrets, API keys, and database credentials is publicly accessible.',
         'Critical', '/.env', 'Immediately deny public access to the .env file in server config.', 'CWE-200', 9.8),
        (1, 'A04:2021', 'FTP Service Exposed on Port 21',
         'An FTP service is running on port 21. FTP transmits credentials and data in plaintext.',
         'Medium', 'Port 21', 'Disable FTP and migrate to SFTP.', 'CWE-319', 6.5),
        # Scan 2: secure-bank.io
        (2, 'A05:2021', 'Server Version Disclosure in HTTP Headers',
         'The web server exposes its version information in HTTP response headers.',
         'Low', 'HTTP Headers', 'Configure web server to hide version info (server_tokens off).', 'CWE-200', 3.1),
        (2, 'A09:2021', 'Insufficient Security Event Logging',
         'The application does not implement comprehensive security event logging.',
         'Medium', 'Application-wide', 'Implement centralized logging with SIEM and real-time triggers.', 'CWE-778', 5.3),
        # Scan 3: legacy-app.example.org
        (3, 'A02:2021', 'Weak TLS Configuration - TLSv1.1 with 1024-bit Key',
         'The server is configured to use TLSv1.1 protocol with a 1024-bit RSA key.',
         'Critical', 'HTTPS Configuration', 'Upgrade to TLSv1.3 and generate key size >= 2048.', 'CWE-326', 9.1),
        (3, 'A05:2021', 'All Security Headers Missing',
         'None of the seven critical security headers are configured.',
         'High', 'All endpoints', 'Configure security headers like X-Frame-Options and HSTS.', 'CWE-693', 8.2),
        (3, 'A03:2021', 'Database Ports Exposed - MySQL and PostgreSQL',
         'Both MySQL (port 3306) and PostgreSQL (port 5432) database services are directly accessible from the network.',
         'Critical', 'Ports 3306, 5432', 'Firewall database access to internal app servers only.', 'CWE-284', 9.4),
        (3, 'A01:2021', 'Multiple Sensitive Directories Exposed',
         'Critical directories including /admin, /backup, /config, /debug, /.env are publicly accessible.',
         'Critical', '/admin, /backup, /config', 'Restrict folder indexing and deny HTTP access to config folders.', 'CWE-538', 9.6)
    ]

    for vuln in vulnerabilities_data:
        cursor.execute(
            """INSERT OR IGNORE INTO vulnerabilities (scan_id, owasp_category, title, description, severity,
               affected_endpoint, remediation, cwe_id, cvss_score)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            vuln
        )

    # -------------------------------------------------------------------------
    # 5. Create Risk Scores (Tenant 1)
    # -------------------------------------------------------------------------
    risk_scores_data = [
        (1, 58.5, 'High', 'C', json.dumps([
            {"factor": "Open Ports", "impact": "medium", "detail": "6 open ports including FTP and MySQL"},
            {"factor": "Missing Headers", "impact": "medium", "detail": "3 of 7 security headers missing"},
            {"factor": "Exposed Directories", "impact": "high", "detail": "Critical files including .env exposed"}
        ]), 'The target acme-corp.com presents a High risk profile. Exposing the .env file is a critical risk.'),
        (2, 12.3, 'Low', 'A', json.dumps([
            {"factor": "Security Headers", "impact": "low", "detail": "All security headers configured"},
            {"factor": "Open Ports", "impact": "low", "detail": "Only 3 ports, SSH filtered"}
        ]), 'The target secure-bank.io demonstrates an excellent security posture.'),
        (3, 91.7, 'Critical', 'F', json.dumps([
            {"factor": "Weak Ciphers", "impact": "high", "detail": "TLSv1.1 with 1024-bit key"},
            {"factor": "Exposed Ports", "impact": "high", "detail": "Directly accessible database ports"},
            {"factor": "Directory Leakage", "impact": "high", "detail": "10 exposed folders"}
        ]), 'The target legacy-app.example.org is in Critical condition. Multiple vulnerabilities allow direct server hijacking.')
    ]

    for rs in risk_scores_data:
        cursor.execute(
            """INSERT OR IGNORE INTO risk_scores (scan_id, risk_score, severity_level, grade,
               contributing_factors, ai_explanation) VALUES (?, ?, ?, ?, ?, ?)""",
            rs
        )

    # -------------------------------------------------------------------------
    # 6. Create Threat Feeds
    # -------------------------------------------------------------------------
    threat_feeds_data = [
        (1, 'acme-corp.com', 'Safe', json.dumps({
            'domain': 'acme-corp.com', 'status': 'Safe', 'risk_score': 12, 'blacklisted': False
        })),
        (2, 'secure-bank.io', 'Safe', json.dumps({
            'domain': 'secure-bank.io', 'status': 'Safe', 'risk_score': 3, 'blacklisted': False
        })),
        (3, 'legacy-app.example.org', 'Suspicious', json.dumps({
            'domain': 'legacy-app.example.org', 'status': 'Suspicious', 'risk_score': 62, 'blacklisted': False
        }))
    ]
    for tf in threat_feeds_data:
        cursor.execute(
            "INSERT OR IGNORE INTO threat_feeds (scan_id, domain, reputation, threat_data) VALUES (?, ?, ?, ?)",
            tf
        )

    # -------------------------------------------------------------------------
    # 7. Create Audit Logs
    # -------------------------------------------------------------------------
    audit_logs_data = [
        (tenant_1_id, admin_id, 'user_registered', 'Admin user account created', '127.0.0.1', 'success', '2026-05-01 08:00:00'),
        (tenant_1_id, analyst_id, 'user_registered', 'Analyst account created', '192.168.1.45', 'success', '2026-05-10 09:30:00'),
        (tenant_1_id, admin_id, 'login_success', 'Admin user logged in successfully', '127.0.0.1', 'success', '2026-06-10 13:55:00'),
        (tenant_1_id, admin_id, 'scan_initiated', 'Full scan initiated for https://acme-corp.com', '127.0.0.1', 'success', '2026-06-10 14:00:00'),
        (tenant_1_id, admin_id, 'scan_initiated', 'Full scan initiated for https://secure-bank.io', '127.0.0.1', 'success', '2026-06-11 09:00:00')
    ]
    for log in audit_logs_data:
        cursor.execute(
            "INSERT OR IGNORE INTO audit_logs (tenant_id, user_id, action, details, ip_address, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            log
        )

    # -------------------------------------------------------------------------
    # 8. Create SIEM Events
    # -------------------------------------------------------------------------
    siem_events_data = [
        (tenant_1_id, 'auth_failure', 'High', '192.168.1.100', 'Multiple failed login attempts detected for admin@cyberguard.ai'),
        (tenant_1_id, 'privilege_escalation', 'Critical', '192.168.1.105', 'User role updated from user to admin by unauthorized token'),
        (tenant_1_id, 'malicious_domain', 'Medium', '10.0.2.15', 'Endpoint accessed domain legacy-app.example.org flagged as suspicious'),
        (tenant_1_id, 'data_exfiltration', 'Critical', '10.0.2.20', 'Abnormal high payload volume (4.2 GB) transferred to external FTP'),
        (tenant_2_id, 'auth_success', 'Low', '127.0.0.1', 'Successful admin login from local interface for Acme Corp')
    ]
    for event in siem_events_data:
        cursor.execute(
            "INSERT INTO siem_events (tenant_id, event_type, severity, source_ip, description) VALUES (?, ?, ?, ?, ?)",
            event
        )

    # -------------------------------------------------------------------------
    # 9. Create CVEs (100+ CVE entries with EPSS scores)
    # -------------------------------------------------------------------------
    cve_products = [
        ('Apache HTTP Server', ['CWE-200', 'CWE-119', 'CWE-400'], 'Web Server'),
        ('Nginx', ['CWE-200', 'CWE-400'], 'Web Server'),
        ('OpenSSH', ['CWE-287', 'CWE-362', 'CWE-20'], 'System Service'),
        ('Linux Kernel', ['CWE-787', 'CWE-269', 'CWE-476'], 'Operating System'),
        ('WordPress Core', ['CWE-79', 'CWE-89', 'CWE-352'], 'CMS Application'),
        ('MySQL Server', ['CWE-89', 'CWE-20', 'CWE-200'], 'Database Service'),
        ('PostgreSQL', ['CWE-89', 'CWE-269'], 'Database Service'),
        ('Redis', ['CWE-284', 'CWE-20'], 'In-Memory Store'),
        ('Kubernetes API Server', ['CWE-269', 'CWE-287'], 'Orchestrator'),
        ('Docker Daemon', ['CWE-269', 'CWE-20'], 'Containerization'),
        ('Windows Server', ['CWE-119', 'CWE-269', 'CWE-20'], 'Operating System'),
        ('FortiOS', ['CWE-787', 'CWE-287', 'CWE-121'], 'Network Appliance'),
        ('GitLab Enterprise', ['CWE-287', 'CWE-74'], 'CI/CD Platform'),
        ('Jenkins', ['CWE-200', 'CWE-269'], 'CI/CD Platform'),
        ('Elasticsearch', ['CWE-284', 'CWE-200'], 'Database Search')
    ]

    cve_severities = ['Critical', 'High', 'Medium', 'Low']

    random.seed(42)  # For reproducible seeding
    cves_seeded = 0

    # Let's write out specific realistic CVEs first (the ones from threat intel)
    specific_cves = [
        ('CVE-2024-3094', 'XZ Utils Backdoor - Supply Chain Compromise',
         'Malicious code was discovered in the upstream tarballs of xz starting from version 5.6.0. The backdoor manipulates the build process to inject code into the resulting liblzma library, enabling unauthorized SSH access.',
         'Critical', 10.0, 0.957, 99.8, '2024-03-29', 'XZ Utils 5.6.0, XZ Utils 5.6.1'),
        ('CVE-2024-21762', 'Fortinet FortiOS Out-of-Bound Write Vulnerability',
         'An out-of-bounds write vulnerability in Fortinet FortiOS allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.',
         'Critical', 9.8, 0.923, 99.5, '2024-02-08', 'FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6'),
        ('CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass',
         'An authentication bypass vulnerability in JetBrains TeamCity before 2023.11.4 allows an unauthenticated attacker to gain administrative control of the TeamCity server via a specially crafted request.',
         'Critical', 9.8, 0.841, 98.9, '2024-03-04', 'TeamCity < 2023.11.4'),
        ('CVE-2024-1709', 'ConnectWise ScreenConnect Authentication Bypass',
         'An authentication bypass vulnerability in ConnectWise ScreenConnect 23.9.7 and prior allows an attacker to create administrative users, delete users, and execute remote code.',
         'Critical', 10.0, 0.965, 99.9, '2024-02-19', 'ScreenConnect <= 23.9.7'),
        ('CVE-2024-6387', 'OpenSSH regreSSHion - Remote Code Execution',
         'A signal handler race condition was found in OpenSSH sshd, leading to potential remote code execution with root privileges.',
         'High', 8.1, 0.428, 91.2, '2024-07-01', 'OpenSSH 8.5p1-9.7p1')
    ]

    for cve in specific_cves:
        cursor.execute(
            """INSERT OR IGNORE INTO cves (cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, references_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cve[0], cve[1], cve[2], cve[3], cve[4], cve[5], cve[6], cve[7], cve[8], json.dumps(['https://nvd.nist.gov/vuln/detail/' + cve[0]]))
        )
        cves_seeded += 1

    # Now generate another 100 random but realistic-looking CVEs
    for i in range(1, 101):
        year = random.choice([2021, 2022, 2023, 2024, 2025, 2026])
        cve_id = f"CVE-{year}-{1000 + i}"
        product_name, cwes, category = random.choice(cve_products)
        cwe = random.choice(cwes)
        severity = random.choice(cve_severities)

        if severity == 'Critical':
            cvss_score = round(random.uniform(9.0, 10.0), 1)
            epss_score = round(random.uniform(0.60, 0.98), 5)
            epss_percentile = round(random.uniform(95.0, 99.9), 2)
        elif severity == 'High':
            cvss_score = round(random.uniform(7.0, 8.9), 1)
            epss_score = round(random.uniform(0.15, 0.59), 5)
            epss_percentile = round(random.uniform(80.0, 94.9), 2)
        elif severity == 'Medium':
            cvss_score = round(random.uniform(4.0, 6.9), 1)
            epss_score = round(random.uniform(0.01, 0.14), 5)
            epss_percentile = round(random.uniform(40.0, 79.9), 2)
        else:
            cvss_score = round(random.uniform(1.0, 3.9), 1)
            epss_score = round(random.uniform(0.0001, 0.009), 5)
            epss_percentile = round(random.uniform(5.0, 39.9), 2)

        title = f"{product_name} {category} vulnerability via {cwe}"
        description = f"An issue was discovered in {product_name} that allows remote attackers to cause a vulnerability classified as {cwe}. This vulnerability can be exploited by craft-injecting commands or exploiting configuration flags."
        published_date = f"{year}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        affected_products = f"{product_name} v{random.randint(1, 5)}.{random.randint(0, 9)}"

        cursor.execute(
            """INSERT OR IGNORE INTO cves (cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, references_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, json.dumps(['https://nvd.nist.gov/vuln/detail/' + cve_id]))
        )
        cves_seeded += 1

    conn.commit()
    conn.close()
    print(f"Database seeded successfully with sample data. Seeded {cves_seeded} CVE entries.")

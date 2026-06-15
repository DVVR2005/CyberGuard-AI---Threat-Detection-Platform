"""
Data access layer for CyberGuard AI - Threat Detection Platform.
Provides functions for CRUD operations on all database tables.
"""

import json
from database import get_db


# =============================================================================
# Helper
# =============================================================================

def _row_to_dict(row):
    """Convert a sqlite3.Row object to a plain dictionary."""
    if row is None:
        return None
    return dict(row)


def _rows_to_list(rows):
    """Convert a list of sqlite3.Row objects to a list of dicts."""
    return [dict(r) for r in rows]


# =============================================================================
# Tenant Functions
# =============================================================================

def create_tenant(name):
    """Create a new tenant organization and return its ID."""
    db = get_db()
    try:
        cursor = db.execute("INSERT INTO tenants (name) VALUES (?)", (name,))
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_tenant_by_id(tenant_id):
    """Get tenant by ID."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_tenant_by_name(name):
    """Get tenant by name."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM tenants WHERE name = ?", (name,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_all_tenants():
    """Get list of all tenants."""
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM tenants ORDER BY name ASC").fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# User Functions
# =============================================================================

def create_user(tenant_id, name, email, password_hash, role='analyst'):
    """Create a new user and return the user id."""
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (tenant_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
            (tenant_id, name, email, password_hash, role)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_user_by_email(email):
    """Get a user by email address. Returns dict or None."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_user_by_id(user_id):
    """Get a user by ID. Returns dict or None."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_all_users(tenant_id=None):
    """Get all users. Optionally filtered by tenant_id. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute("SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


def update_user(user_id, **kwargs):
    """Update user fields dynamically. Returns True if a row was updated."""
    allowed_fields = {'name', 'email', 'role', 'status', 'failed_attempts', 'locked_until', 'password_hash', 'tenant_id'}
    fields = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not fields:
        return False

    set_clause = ', '.join(f"{k} = ?" for k in fields.keys())
    values = list(fields.values()) + [user_id]

    db = get_db()
    try:
        cursor = db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def delete_user(user_id):
    """Delete a user by ID. Returns True if a row was deleted."""
    db = get_db()
    try:
        cursor = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def increment_failed_attempts(user_id):
    """Increment failed login attempts. Returns the new count."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,)
        )
        db.commit()
        row = db.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
        return row['failed_attempts'] if row else 0
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def reset_failed_attempts(user_id):
    """Reset failed login attempts to zero."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,)
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def lock_user(user_id, until_datetime):
    """Lock a user account until the specified datetime string."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET locked_until = ? WHERE id = ?",
            (until_datetime, user_id)
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


# =============================================================================
# Scan Functions
# =============================================================================

def create_scan(tenant_id, user_id, target_url, port_results, ssl_results, header_results,
                directory_results, started_at, completed_at, status='completed', scan_type='full'):
    """Create a new scan record. JSON fields should be pre-serialized strings. Returns scan id."""
    db = get_db()
    try:
        cursor = db.execute(
            """INSERT INTO scans (tenant_id, user_id, target_url, status, scan_type, port_results,
               ssl_results, header_results, directory_results, started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, user_id, target_url, status, scan_type, port_results,
             ssl_results, header_results, directory_results, started_at, completed_at)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def update_scan_status(scan_id, status, completed_at=None, **kwargs):
    """Update background scan status."""
    db = get_db()
    try:
        set_clauses = ["status = ?"]
        values = [status]
        if completed_at:
            set_clauses.append("completed_at = ?")
            values.append(completed_at)
        
        for k, v in kwargs.items():
            set_clauses.append(f"{k} = ?")
            values.append(v)
            
        values.append(scan_id)
        db.execute(f"UPDATE scans SET {', '.join(set_clauses)} WHERE id = ?", values)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_scan_by_id(scan_id, tenant_id=None):
    """Get a scan by ID, optionally filtered by tenant_id. Returns dict or None."""
    db = get_db()
    try:
        if tenant_id is not None:
            row = db.execute("SELECT * FROM scans WHERE id = ? AND tenant_id = ?", (scan_id, tenant_id)).fetchone()
        else:
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_scans_by_user(user_id, tenant_id=None):
    """Get all scans for a specific user, optionally filtered by tenant_id. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                "SELECT * FROM scans WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC",
                (user_id, tenant_id)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


def get_all_scans(tenant_id=None):
    """Get all scans, optionally filtered by tenant_id. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute("SELECT * FROM scans WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


def delete_scan(scan_id, tenant_id=None):
    """Delete a scan and its cascaded data. Returns True if a row was deleted."""
    db = get_db()
    try:
        if tenant_id is not None:
            cursor = db.execute("DELETE FROM scans WHERE id = ? AND tenant_id = ?", (scan_id, tenant_id))
        else:
            cursor = db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def count_scans_by_user(user_id, tenant_id=None):
    """Count total scans for a user within a tenant."""
    db = get_db()
    try:
        if tenant_id is not None:
            row = db.execute(
                "SELECT COUNT(*) as cnt FROM scans WHERE user_id = ? AND tenant_id = ?", (user_id, tenant_id)
            ).fetchone()
        else:
            row = db.execute(
                "SELECT COUNT(*) as cnt FROM scans WHERE user_id = ?", (user_id,)
            ).fetchone()
        return row['cnt']
    finally:
        db.close()


# =============================================================================
# Vulnerability Functions
# =============================================================================

def create_vulnerability(scan_id, owasp_category, title, description, severity,
                         affected_endpoint, remediation, cwe_id, cvss_score):
    """Create a vulnerability record. Returns vulnerability id."""
    db = get_db()
    try:
        cursor = db.execute(
            """INSERT INTO vulnerabilities (scan_id, owasp_category, title, description,
               severity, affected_endpoint, remediation, cwe_id, cvss_score)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, owasp_category, title, description, severity,
             affected_endpoint, remediation, cwe_id, cvss_score)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_vulnerabilities_by_scan(scan_id):
    """Get all vulnerabilities for a specific scan. Returns list of dicts."""
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss_score DESC",
            (scan_id,)
        ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


def count_vulnerabilities_by_severity(tenant_id=None):
    """Count vulnerabilities grouped by severity. Returns dict like {'Critical': 5, ...}."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                """SELECT v.severity, COUNT(*) as cnt FROM vulnerabilities v
                   JOIN scans s ON v.scan_id = s.id
                   WHERE s.tenant_id = ?
                   GROUP BY v.severity""",
                (tenant_id,)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
            ).fetchall()
        return {row['severity']: row['cnt'] for row in rows}
    finally:
        db.close()


def get_all_vulnerabilities(tenant_id=None):
    """Get all vulnerabilities. Optionally filtered by tenant_id. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                """SELECT v.* FROM vulnerabilities v
                   JOIN scans s ON v.scan_id = s.id
                   WHERE s.tenant_id = ?
                   ORDER BY v.cvss_score DESC""",
                (tenant_id,)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM vulnerabilities ORDER BY cvss_score DESC"
            ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# Risk Score Functions
# =============================================================================

def create_risk_score(scan_id, risk_score, severity_level, grade,
                      contributing_factors, ai_explanation):
    """Create a risk score record. contributing_factors should be a JSON string. Returns id."""
    db = get_db()
    try:
        cursor = db.execute(
            """INSERT INTO risk_scores (scan_id, risk_score, severity_level, grade,
               contributing_factors, ai_explanation) VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_id, risk_score, severity_level, grade, contributing_factors, ai_explanation)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_risk_score_by_scan(scan_id):
    """Get risk score for a specific scan. Returns dict or None."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM risk_scores WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


# =============================================================================
# Threat Feed Functions
# =============================================================================

def create_threat_feed(scan_id, domain, reputation, threat_data):
    """Create a threat feed record. threat_data should be a JSON string. Returns id."""
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO threat_feeds (scan_id, domain, reputation, threat_data) VALUES (?, ?, ?, ?)",
            (scan_id, domain, reputation, threat_data)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_threat_feeds_by_scan(scan_id):
    """Get all threat feeds for a specific scan. Returns list of dicts."""
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM threat_feeds WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# Report Functions
# =============================================================================

def create_report(tenant_id, scan_id, user_id, filename, filepath):
    """Create a report record. Returns report id."""
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO reports (tenant_id, scan_id, user_id, filename, filepath) VALUES (?, ?, ?, ?, ?)",
            (tenant_id, scan_id, user_id, filename, filepath)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_reports_by_user(user_id, tenant_id=None):
    """Get all reports for a specific user, joined with scan target_url. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                """SELECT r.*, s.target_url FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   WHERE r.user_id = ? AND r.tenant_id = ? ORDER BY r.created_at DESC""",
                (user_id, tenant_id)
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT r.*, s.target_url FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   WHERE r.user_id = ? ORDER BY r.created_at DESC""",
                (user_id,)
            ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


def get_report_by_id(report_id, tenant_id=None):
    """Get a report by ID. Returns dict or None."""
    db = get_db()
    try:
        if tenant_id is not None:
            row = db.execute(
                """SELECT r.*, s.target_url, s.user_id as scan_user_id FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   WHERE r.id = ? AND r.tenant_id = ?""",
                (report_id, tenant_id)
            ).fetchone()
        else:
            row = db.execute(
                """SELECT r.*, s.target_url, s.user_id as scan_user_id FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   WHERE r.id = ?""",
                (report_id,)
            ).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def get_all_reports(tenant_id=None):
    """Get all reports joined with scan target_url. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                """SELECT r.*, s.target_url FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   WHERE r.tenant_id = ?
                   ORDER BY r.created_at DESC""",
                (tenant_id,)
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT r.*, s.target_url FROM reports r
                   JOIN scans s ON r.scan_id = s.id
                   ORDER BY r.created_at DESC"""
            ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# Audit Log Functions
# =============================================================================

def create_audit_log(tenant_id, user_id, action, details, ip_address=None, status='success'):
    """Create an audit log entry. Returns log id."""
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO audit_logs (tenant_id, user_id, action, details, ip_address, status) VALUES (?, ?, ?, ?, ?, ?)",
            (tenant_id, user_id, action, details, ip_address, status)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_all_audit_logs(limit=100, tenant_id=None):
    """Get audit logs with optional limit, joined with user email. Returns list of dicts."""
    db = get_db()
    try:
        if tenant_id is not None:
            rows = db.execute(
                """SELECT a.*, u.email as user_email FROM audit_logs a
                   LEFT JOIN users u ON a.user_id = u.id
                   WHERE a.tenant_id = ?
                   ORDER BY a.created_at DESC LIMIT ?""",
                (tenant_id, limit)
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT a.*, u.email as user_email FROM audit_logs a
                   LEFT JOIN users u ON a.user_id = u.id
                   ORDER BY a.created_at DESC LIMIT ?""",
                (limit,)
            ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# SIEM Event Functions
# =============================================================================

def create_siem_event(tenant_id, event_type, severity, source_ip, description):
    """Create a new SIEM security event log. Returns event id."""
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO siem_events (tenant_id, event_type, severity, source_ip, description) VALUES (?, ?, ?, ?, ?)",
            (tenant_id, event_type, severity, source_ip, description)
        )
        db.commit()
        return cursor.lastrowid
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_siem_events(tenant_id=None, limit=100, severity=None, search_query=None):
    """Fetch and search SIEM events, partitioned by tenant."""
    db = get_db()
    try:
        query = "SELECT * FROM siem_events"
        params = []
        conditions = []

        if tenant_id is not None:
            conditions.append("tenant_id = ?")
            params.append(tenant_id)

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        if search_query:
            conditions.append("(event_type LIKE ? OR description LIKE ? OR source_ip LIKE ?)")
            like_val = f"%{search_query}%"
            params.extend([like_val, like_val, like_val])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(query, params).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# CVE Functions
# =============================================================================

def create_cve(cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, references_json):
    """Create a new CVE entry in database."""
    db = get_db()
    try:
        db.execute(
            """INSERT OR REPLACE INTO cves (cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, references_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cve_id, title, description, severity, cvss_score, epss_score, epss_percentile, published_date, affected_products, references_json)
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_cve_by_id(cve_id):
    """Retrieve CVE details."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        db.close()


def search_cves(query=None, min_cvss=0.0, min_epss=0.0, severity=None, sort_by='cvss_score', limit=50):
    """Search and filter CVE database."""
    db = get_db()
    try:
        sql = "SELECT * FROM cves"
        conditions = ["cvss_score >= ?", "epss_score >= ?"]
        params = [min_cvss, min_epss]

        if query:
            conditions.append("(cve_id LIKE ? OR title LIKE ? OR description LIKE ? OR affected_products LIKE ?)")
            like_val = f"%{query}%"
            params.extend([like_val, like_val, like_val, like_val])

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        sql += " WHERE " + " AND ".join(conditions)

        # Enforce valid sorting fields
        if sort_by not in ('cvss_score', 'epss_score', 'published_date', 'cve_id'):
            sort_by = 'cvss_score'
        sql += f" ORDER BY {sort_by} DESC LIMIT ?"
        params.append(limit)

        rows = db.execute(sql, params).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()


# =============================================================================
# Dashboard Functions
# =============================================================================

def get_dashboard_stats(tenant_id=None, user_id=None):
    """
    Get dashboard statistics, scoped by tenant_id. If user_id is provided,
    scope further to user's scans only (for standard users/analysts).
    """
    db = get_db()
    try:
        # Build scan filter condition
        scan_conds = []
        scan_params = []

        if tenant_id is not None:
            scan_conds.append("tenant_id = ?")
            scan_params.append(tenant_id)

        if user_id is not None:
            scan_conds.append("user_id = ?")
            scan_params.append(user_id)

        scan_where = f" WHERE {' AND '.join(scan_conds)}" if scan_conds else ""

        # Total Scans
        total_scans = db.execute(f"SELECT COUNT(*) as cnt FROM scans{scan_where}", scan_params).fetchone()['cnt']

        # Total Vulnerabilities & Critical Count
        vuln_conds = []
        vuln_params = []
        if tenant_id is not None:
            vuln_conds.append("s.tenant_id = ?")
            vuln_params.append(tenant_id)
        if user_id is not None:
            vuln_conds.append("s.user_id = ?")
            vuln_params.append(user_id)

        vuln_where = f" WHERE {' AND '.join(vuln_conds)}" if vuln_conds else ""

        total_vulns = db.execute(
            f"SELECT COUNT(*) as cnt FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id{vuln_where}",
            vuln_params
        ).fetchone()['cnt']

        critical_conds = list(vuln_conds) + ["v.severity = 'Critical'"]
        critical_params = list(vuln_params)
        critical_where = f" WHERE {' AND '.join(critical_conds)}"
        critical_count = db.execute(
            f"SELECT COUNT(*) as cnt FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id{critical_where}",
            critical_params
        ).fetchone()['cnt']

        # Average Risk Score
        avg_conds = []
        avg_params = []
        if tenant_id is not None:
            avg_conds.append("s.tenant_id = ?")
            avg_params.append(tenant_id)
        if user_id is not None:
            avg_conds.append("s.user_id = ?")
            avg_params.append(user_id)

        avg_where = f" WHERE {' AND '.join(avg_conds)}" if avg_conds else ""
        avg_score_row = db.execute(
            f"SELECT AVG(rs.risk_score) as avg_score FROM risk_scores rs JOIN scans s ON rs.scan_id = s.id{avg_where}",
            avg_params
        ).fetchone()
        avg_risk = round(avg_score_row['avg_score'], 1) if avg_score_row['avg_score'] else 0.0

        # Scans This Month
        month_conds = list(scan_conds) + ["created_at >= datetime('now', 'start of month')"]
        month_where = f" WHERE {' AND '.join(month_conds)}"
        scans_this_month = db.execute(f"SELECT COUNT(*) as cnt FROM scans{month_where}", scan_params).fetchone()['cnt']

        # Most Common Vuln
        common_where = f" WHERE {' AND '.join(vuln_conds)}" if vuln_conds else ""
        most_common_row = db.execute(
            f"""SELECT v.owasp_category, COUNT(*) as cnt FROM vulnerabilities v
               JOIN scans s ON v.scan_id = s.id{common_where}
               GROUP BY v.owasp_category ORDER BY cnt DESC LIMIT 1""",
            vuln_params
        ).fetchone()
        most_common_vuln = most_common_row['owasp_category'] if most_common_row else 'N/A'

        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'critical_count': critical_count,
            'avg_risk_score': avg_risk,
            'scans_this_month': scans_this_month,
            'most_common_vuln': most_common_vuln
        }
    finally:
        db.close()


def get_dashboard_charts(tenant_id=None, user_id=None):
    """
    Get aggregated chart data, scoped by tenant_id and user_id.
    """
    db = get_db()
    try:
        vuln_conds = []
        vuln_params = []
        if tenant_id is not None:
            vuln_conds.append("s.tenant_id = ?")
            vuln_params.append(tenant_id)
        if user_id is not None:
            vuln_conds.append("s.user_id = ?")
            vuln_params.append(user_id)

        vuln_where = f" WHERE {' AND '.join(vuln_conds)}" if vuln_conds else ""

        # Vulnerability distribution by OWASP category
        vuln_dist_rows = db.execute(
            f"""SELECT v.owasp_category, COUNT(*) as cnt FROM vulnerabilities v
               JOIN scans s ON v.scan_id = s.id{vuln_where}
               GROUP BY v.owasp_category ORDER BY v.owasp_category""",
            vuln_params
        ).fetchall()

        # Severity breakdown
        severity_rows = db.execute(
            f"""SELECT v.severity, COUNT(*) as cnt FROM vulnerabilities v
               JOIN scans s ON v.scan_id = s.id{vuln_where}
               GROUP BY v.severity ORDER BY
               CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
               WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 END""",
            vuln_params
        ).fetchall()

        # Risk trend (risk score over time)
        risk_conds = []
        risk_params = []
        if tenant_id is not None:
            risk_conds.append("s.tenant_id = ?")
            risk_params.append(tenant_id)
        if user_id is not None:
            risk_conds.append("s.user_id = ?")
            risk_params.append(user_id)

        risk_where = f" WHERE {' AND '.join(risk_conds)}" if risk_conds else ""
        risk_trend_rows = db.execute(
            f"""SELECT s.created_at as scan_date, rs.risk_score
               FROM risk_scores rs JOIN scans s ON rs.scan_id = s.id{risk_where}
               ORDER BY s.created_at""",
            risk_params
        ).fetchall()

        # Monthly scans
        scan_conds = []
        scan_params = []
        if tenant_id is not None:
            scan_conds.append("tenant_id = ?")
            scan_params.append(tenant_id)
        if user_id is not None:
            scan_conds.append("user_id = ?")
            scan_params.append(user_id)

        scan_where = f" WHERE {' AND '.join(scan_conds)}" if scan_conds else ""
        monthly_rows = db.execute(
            f"""SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
               FROM scans{scan_where} GROUP BY month ORDER BY month""",
            scan_params
        ).fetchall()

        # Format chart data
        vuln_distribution = [
            {'category': r['owasp_category'], 'count': r['cnt']} for r in vuln_dist_rows
        ]

        severity_breakdown = [
            {'severity': r['severity'], 'count': r['cnt']} for r in severity_rows
        ]

        risk_trend = [
            {'date': r['scan_date'][:10], 'score': r['risk_score']} for r in risk_trend_rows
        ]

        month_names = {
            '01': 'Jan', '02': 'Feb', '03': 'Mar', '04': 'Apr',
            '05': 'May', '06': 'Jun', '07': 'Jul', '08': 'Aug',
            '09': 'Sep', '10': 'Oct', '11': 'Nov', '12': 'Dec'
        }
        monthly_scans = [
            {
                'month': month_names.get(r['month'].split('-')[1], r['month']) if '-' in r['month'] else r['month'],
                'count': r['cnt']
            } for r in monthly_rows
        ]

        return {
            'vuln_distribution': vuln_distribution,
            'severity_breakdown': severity_breakdown,
            'risk_trend': risk_trend,
            'monthly_scans': monthly_scans
        }
    finally:
        db.close()


def get_recent_scans(tenant_id=None, user_id=None, limit=5):
    """
    Get the most recent scans with risk score and vulnerability count, scoped to tenant and user.
    """
    db = get_db()
    try:
        conds = []
        params = []

        if tenant_id is not None:
            conds.append("s.tenant_id = ?")
            params.append(tenant_id)

        if user_id is not None:
            conds.append("s.user_id = ?")
            params.append(user_id)

        where_clause = f" WHERE {' AND '.join(conds)}" if conds else ""
        params.append(limit)

        rows = db.execute(
            f"""SELECT s.id, s.target_url, s.status, s.created_at,
               rs.risk_score, rs.grade,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) as vulnerability_count
               FROM scans s
               LEFT JOIN risk_scores rs ON rs.scan_id = s.id
               {where_clause}
               ORDER BY s.created_at DESC LIMIT ?""",
            params
        ).fetchall()
        return _rows_to_list(rows)
    finally:
        db.close()

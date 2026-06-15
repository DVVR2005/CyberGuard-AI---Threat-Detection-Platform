"""
OWASP classification engine for CyberGuard AI.
Analyzes scan results and classifies findings into OWASP Top 10 (2021) categories.
"""


def classify_vulnerabilities(scan_results):
    """
    Takes full scan results and classifies findings into OWASP Top 10 categories.
    Returns list of vulnerability dicts with category, title, description, severity,
    affected_endpoint, remediation, cwe_id, and cvss_score.
    """
    vulnerabilities = []

    port_results = scan_results.get('port_results', [])
    ssl_results = scan_results.get('ssl_results', {})
    header_results = scan_results.get('header_results', [])
    directory_results = scan_results.get('directory_results', [])

    # -------------------------------------------------------------------------
    # Analyze Port Results
    # -------------------------------------------------------------------------
    open_ports = [p for p in port_results if p.get('state') == 'open']

    # Check for open database ports -> A03:2021 Injection
    db_ports = [p for p in open_ports if p['port'] in (3306, 5432, 27017)]
    if db_ports:
        port_list = ', '.join(f"{p['port']} ({p['service']} {p['version']})" for p in db_ports)
        vulnerabilities.append({
            'owasp_category': 'A03:2021',
            'title': 'Database Services Directly Accessible',
            'description': (
                f"The following database services are directly accessible from the network: {port_list}. "
                f"Exposed database ports allow attackers to attempt brute-force authentication, exploit known "
                f"database vulnerabilities, and potentially execute SQL injection attacks directly against the "
                f"database engine bypassing application-level controls."
            ),
            'severity': 'Critical' if len(db_ports) > 1 else 'High',
            'affected_endpoint': ', '.join(f"Port {p['port']}" for p in db_ports),
            'remediation': (
                "1. Configure firewall rules to restrict database access to application servers only. "
                "2. Use network segmentation to isolate database servers in a private subnet. "
                "3. Implement strong authentication with complex passwords and certificate-based auth. "
                "4. Consider using SSH tunnels or VPN for any remote database management needs. "
                "5. Enable database audit logging to monitor access attempts."
            ),
            'cwe_id': 'CWE-284',
            'cvss_score': 9.4 if len(db_ports) > 1 else 8.6
        })

    # Check for FTP port -> A04:2021 Insecure Design
    ftp_ports = [p for p in open_ports if p['port'] == 21]
    if ftp_ports:
        ftp_info = ftp_ports[0]
        vulnerabilities.append({
            'owasp_category': 'A04:2021',
            'title': 'Insecure FTP Service Active',
            'description': (
                f"An FTP service ({ftp_info['version']}) is running on port 21. FTP is an inherently "
                f"insecure protocol that transmits credentials and file data in plaintext over the network. "
                f"Any attacker performing network traffic analysis or man-in-the-middle attacks can intercept "
                f"usernames, passwords, and transferred file contents."
            ),
            'severity': 'Medium',
            'affected_endpoint': 'Port 21',
            'remediation': (
                "1. Disable FTP service and migrate to SFTP (SSH File Transfer Protocol) or SCP. "
                "2. If FTP is absolutely required, enforce FTPS (FTP over TLS) with strong certificates. "
                "3. Restrict FTP access to specific trusted IP addresses via firewall rules. "
                "4. Implement rate limiting on authentication attempts to prevent brute-force attacks."
            ),
            'cwe_id': 'CWE-319',
            'cvss_score': 6.5
        })

    # Check for Redis port -> A05:2021 Security Misconfiguration
    redis_ports = [p for p in open_ports if p['port'] == 6379]
    if redis_ports:
        redis_info = redis_ports[0]
        vulnerabilities.append({
            'owasp_category': 'A05:2021',
            'title': 'Redis Service Exposed Without Access Restrictions',
            'description': (
                f"A Redis in-memory data store ({redis_info['version']}) is accessible on port 6379. "
                f"Redis instances are frequently deployed without authentication enabled by default. "
                f"An exposed Redis service can be exploited for unauthorized data access, cache poisoning, "
                f"denial of service attacks, or even remote code execution through Redis modules."
            ),
            'severity': 'High',
            'affected_endpoint': 'Port 6379',
            'remediation': (
                "1. Configure Redis to bind only to localhost (127.0.0.1) or internal network interfaces. "
                "2. Enable Redis AUTH with a strong password using the 'requirepass' configuration. "
                "3. Use firewall rules to restrict access to the Redis port from trusted sources only. "
                "4. Disable dangerous commands (FLUSHALL, CONFIG, DEBUG) using the 'rename-command' directive. "
                "5. Enable TLS encryption for Redis connections if available."
            ),
            'cwe_id': 'CWE-284',
            'cvss_score': 8.1
        })

    # Check for Elasticsearch -> A05:2021 Security Misconfiguration
    es_ports = [p for p in open_ports if p['port'] == 9200]
    if es_ports:
        vulnerabilities.append({
            'owasp_category': 'A05:2021',
            'title': 'Elasticsearch Service Publicly Accessible',
            'description': (
                f"An Elasticsearch service ({es_ports[0]['version']}) is accessible on port 9200. "
                f"Publicly exposed Elasticsearch instances can lead to massive data leaks, as the entire "
                f"index contents can be enumerated and downloaded without authentication."
            ),
            'severity': 'Critical',
            'affected_endpoint': 'Port 9200',
            'remediation': (
                "1. Enable Elasticsearch security features (X-Pack Security or OpenSearch Security). "
                "2. Restrict network access using firewall rules to internal application servers. "
                "3. Configure TLS/SSL for transport and HTTP layers. "
                "4. Implement role-based access control for all indices and operations."
            ),
            'cwe_id': 'CWE-284',
            'cvss_score': 9.1
        })

    # -------------------------------------------------------------------------
    # Analyze SSL Results
    # -------------------------------------------------------------------------
    if ssl_results:
        grade = ssl_results.get('grade', 'A')
        cipher = ssl_results.get('cipher_strength', 'strong')
        protocol = ssl_results.get('protocol', 'TLSv1.3')
        key_size = ssl_results.get('key_size', 2048)

        # Weak or failed SSL -> A02:2021 Cryptographic Failures
        if grade in ('D', 'F') or cipher == 'weak':
            vulnerabilities.append({
                'owasp_category': 'A02:2021',
                'title': f'Weak TLS Configuration - {protocol} with Grade {grade}',
                'description': (
                    f"The server's TLS configuration received a grade of {grade} with {cipher} cipher strength. "
                    f"The server is using {protocol} protocol with a {key_size}-bit key. "
                    f"{'TLSv1.0 and TLSv1.1 are deprecated and contain known vulnerabilities including POODLE and BEAST attacks. ' if protocol in ('TLSv1.0', 'TLSv1.1') else ''}"
                    f"{'A key size of 1024 bits is below the recommended minimum of 2048 bits and is susceptible to factorization attacks.' if key_size < 2048 else ''}"
                ),
                'severity': 'Critical' if grade == 'F' else 'High',
                'affected_endpoint': 'HTTPS Configuration',
                'remediation': (
                    "1. Upgrade to TLSv1.3 as the primary protocol with TLSv1.2 as minimum fallback. "
                    "2. Generate a new RSA key with at least 2048 bits (4096 recommended for high-security). "
                    "3. Disable all cipher suites using RC4, DES, 3DES, and MD5. "
                    "4. Enable only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305). "
                    "5. Follow Mozilla SSL Configuration Generator guidelines for your web server."
                ),
                'cwe_id': 'CWE-326',
                'cvss_score': 9.1 if grade == 'F' else 7.5
            })
        elif grade in ('B', 'C'):
            vulnerabilities.append({
                'owasp_category': 'A02:2021',
                'title': f'Moderate TLS Configuration - Grade {grade}',
                'description': (
                    f"The server's TLS configuration received a grade of {grade}. While the current setup "
                    f"using {protocol} with {key_size}-bit key provides baseline security, upgrading to "
                    f"TLSv1.3 with stronger cipher suites would significantly improve the cryptographic posture."
                ),
                'severity': 'Medium',
                'affected_endpoint': 'HTTPS Configuration',
                'remediation': (
                    "1. Upgrade to TLSv1.3 while maintaining TLSv1.2 as fallback for compatibility. "
                    "2. Review and optimize cipher suite configuration for forward secrecy. "
                    "3. Disable CBC-mode ciphers and prefer AEAD cipher suites. "
                    "4. Consider implementing OCSP stapling for improved certificate validation performance."
                ),
                'cwe_id': 'CWE-326',
                'cvss_score': 5.3
            })

        if not ssl_results.get('valid', True):
            vulnerabilities.append({
                'owasp_category': 'A02:2021',
                'title': 'Invalid or Expired SSL Certificate',
                'description': (
                    "The SSL certificate is either invalid, expired, or self-signed. Users will receive "
                    "browser security warnings, reducing trust and potentially training users to ignore "
                    "security alerts. This also makes the site vulnerable to man-in-the-middle attacks."
                ),
                'severity': 'High',
                'affected_endpoint': 'HTTPS Configuration',
                'remediation': (
                    "1. Obtain and install a valid SSL certificate from a trusted Certificate Authority. "
                    "2. Set up automatic certificate renewal (e.g., using certbot for Let's Encrypt). "
                    "3. Verify the certificate chain is complete and properly configured. "
                    "4. Implement certificate monitoring to alert before expiration."
                ),
                'cwe_id': 'CWE-295',
                'cvss_score': 7.4
            })

    # -------------------------------------------------------------------------
    # Analyze Header Results
    # -------------------------------------------------------------------------
    missing_headers = [h for h in header_results if not h.get('present', False)]
    warning_headers = [h for h in header_results if h.get('status') == 'warning']

    if missing_headers:
        missing_names = [h['header'] for h in missing_headers]

        # Check for missing CSP specifically
        if 'Content-Security-Policy' in missing_names:
            vulnerabilities.append({
                'owasp_category': 'A05:2021',
                'title': 'Missing Content-Security-Policy Header',
                'description': (
                    "The Content-Security-Policy (CSP) header is not configured. CSP is a critical "
                    "defense-in-depth mechanism that prevents cross-site scripting (XSS), clickjacking, "
                    "and other code injection attacks by specifying approved content sources. Without CSP, "
                    "the application relies solely on output encoding for XSS prevention."
                ),
                'severity': 'High',
                'affected_endpoint': 'All endpoints',
                'remediation': (
                    "1. Implement a strict Content-Security-Policy starting with: \"default-src 'self'; "
                    "script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:\". "
                    "2. Use CSP reporting to identify violations before enforcing strict policies. "
                    "3. Avoid 'unsafe-inline' and 'unsafe-eval' where possible. "
                    "4. Consider using nonce-based or hash-based CSP for inline scripts."
                ),
                'cwe_id': 'CWE-693',
                'cvss_score': 7.5
            })

        # Check for missing HSTS -> A07:2021
        if 'Strict-Transport-Security' in missing_names:
            vulnerabilities.append({
                'owasp_category': 'A07:2021',
                'title': 'Missing HTTP Strict Transport Security (HSTS)',
                'description': (
                    "The Strict-Transport-Security header is not set. Without HSTS, users can be "
                    "downgraded from HTTPS to HTTP through SSL stripping attacks. This is particularly "
                    "dangerous for authentication pages and session management."
                ),
                'severity': 'Medium',
                'affected_endpoint': 'All endpoints',
                'remediation': (
                    "1. Add the Strict-Transport-Security header: \"max-age=63072000; includeSubDomains; preload\". "
                    "2. Ensure all subdomains also support HTTPS before adding includeSubDomains. "
                    "3. Submit the domain for HSTS preloading at hstspreload.org. "
                    "4. Start with a shorter max-age during testing, then increase to 2 years."
                ),
                'cwe_id': 'CWE-523',
                'cvss_score': 5.4
            })

        # Group remaining missing headers as general misconfiguration
        other_missing = [h for h in missing_names
                         if h not in ('Content-Security-Policy', 'Strict-Transport-Security')]
        if other_missing:
            vulnerabilities.append({
                'owasp_category': 'A05:2021',
                'title': f'Missing Security Headers: {", ".join(other_missing)}',
                'description': (
                    f"The following security headers are not configured: {', '.join(other_missing)}. "
                    f"These headers provide important defense-in-depth protections against common "
                    f"web attacks including clickjacking, MIME-type confusion, XSS, and information leakage. "
                    f"Each missing header represents a reduced layer of client-side security."
                ),
                'severity': 'Medium' if len(other_missing) <= 2 else 'High',
                'affected_endpoint': 'All endpoints',
                'remediation': (
                    "Configure the following headers in your web server: "
                    + '; '.join(f"{h}: [recommended value]" for h in other_missing) + ". "
                    "Refer to OWASP Secure Headers Project for recommended values for each header."
                ),
                'cwe_id': 'CWE-693',
                'cvss_score': 5.8 if len(other_missing) <= 2 else 7.1
            })

    # -------------------------------------------------------------------------
    # Analyze Directory Results
    # -------------------------------------------------------------------------
    found_dirs = [d for d in directory_results if d.get('found', False)]

    # .env exposed -> A02:2021 Cryptographic Failures (secrets exposure)
    env_dirs = [d for d in found_dirs if d['path'] == '/.env' and d.get('status') == 200]
    if env_dirs:
        vulnerabilities.append({
            'owasp_category': 'A02:2021',
            'title': 'Environment Configuration File Exposed (.env)',
            'description': (
                "The .env file is publicly accessible and returns HTTP 200. Environment files typically "
                "contain application secrets including database credentials, API keys, JWT secrets, "
                "email service passwords, and third-party service tokens. Exposure of these secrets "
                "can lead to complete application compromise."
            ),
            'severity': 'Critical',
            'affected_endpoint': '/.env',
            'remediation': (
                "1. Immediately configure the web server to deny access to all dotfiles (.*). "
                "2. Rotate ALL credentials and secrets that were in the exposed .env file. "
                "3. Add .env to .gitignore to prevent version control exposure. "
                "4. Use server-level environment variables or a secrets management service instead. "
                "5. Audit access logs to determine if the file was accessed by unauthorized parties."
            ),
            'cwe_id': 'CWE-200',
            'cvss_score': 9.8
        })

    # .git exposed -> A02:2021 Cryptographic Failures (source code/secrets)
    git_dirs = [d for d in found_dirs if d['path'] == '/.git' and d.get('status') in (200, 301)]
    if git_dirs:
        vulnerabilities.append({
            'owasp_category': 'A02:2021',
            'title': 'Git Repository Exposed (.git)',
            'description': (
                "The .git directory is accessible, potentially exposing the complete source code "
                "repository including full commit history, branches, configuration files, and any "
                "secrets that were ever committed. Attackers can reconstruct the entire codebase "
                "and search through history for credentials, API keys, and security vulnerabilities."
            ),
            'severity': 'Critical',
            'affected_endpoint': '/.git',
            'remediation': (
                "1. Block access to the .git directory via web server configuration rules. "
                "2. Audit the entire repository history for committed secrets using tools like git-secrets, "
                "truffleHog, or gitleaks. "
                "3. Rotate any secrets found in the repository history. "
                "4. Consider using a .gitignore and pre-commit hooks to prevent future secret leaks."
            ),
            'cwe_id': 'CWE-200',
            'cvss_score': 9.3
        })

    # Admin panel exposed -> A01:2021 Broken Access Control
    admin_dirs = [d for d in found_dirs if d['path'] == '/admin' and d.get('status') == 200]
    if admin_dirs:
        vulnerabilities.append({
            'owasp_category': 'A01:2021',
            'title': 'Administrative Panel Publicly Accessible',
            'description': (
                "The administrative panel at /admin is directly accessible (HTTP 200) without "
                "IP-based restrictions, VPN requirements, or additional access controls. This "
                "exposes the management interface to brute-force attacks, credential stuffing, "
                "and potential unauthorized access from any network location."
            ),
            'severity': 'High',
            'affected_endpoint': '/admin',
            'remediation': (
                "1. Restrict access to the admin panel using IP whitelisting or VPN requirements. "
                "2. Implement multi-factor authentication for all administrative accounts. "
                "3. Consider moving the admin panel to a non-standard, unpredictable URL path. "
                "4. Implement account lockout after failed authentication attempts. "
                "5. Add brute-force protection with progressive delays."
            ),
            'cwe_id': 'CWE-284',
            'cvss_score': 8.2
        })

    # Debug/phpinfo pages -> A05:2021 Security Misconfiguration
    debug_dirs = [d for d in found_dirs
                  if d['path'] in ('/debug', '/phpinfo') and d.get('status') == 200]
    if debug_dirs:
        paths = ', '.join(d['path'] for d in debug_dirs)
        vulnerabilities.append({
            'owasp_category': 'A05:2021',
            'title': f'Debug/Information Disclosure Endpoints Active ({paths})',
            'description': (
                f"Debug or information disclosure endpoints ({paths}) are accessible in the production "
                f"environment. These pages expose detailed system information including PHP version, "
                f"server configuration, loaded modules, environment variables, and internal file paths "
                f"that significantly aid attacker reconnaissance."
            ),
            'severity': 'High',
            'affected_endpoint': paths,
            'remediation': (
                "1. Disable all debug endpoints and information disclosure pages in production. "
                "2. Remove phpinfo() calls from production code entirely. "
                "3. Ensure DEBUG mode is set to False in production configuration. "
                "4. Implement proper error handling that returns generic error messages to users."
            ),
            'cwe_id': 'CWE-200',
            'cvss_score': 7.5
        })

    # Backup files -> A08:2021 Software and Data Integrity Failures
    backup_dirs = [d for d in found_dirs if d['path'] == '/backup' and d.get('status') == 200]
    if backup_dirs:
        vulnerabilities.append({
            'owasp_category': 'A08:2021',
            'title': 'Backup Directory Publicly Accessible',
            'description': (
                "The /backup directory is publicly accessible and returns HTTP 200, indicating that "
                "backup files may be downloadable. Database dumps, application backups, and configuration "
                "archives often contain sensitive data including credentials, personal information, "
                "and business-critical data."
            ),
            'severity': 'High',
            'affected_endpoint': '/backup',
            'remediation': (
                "1. Remove all backup files from web-accessible directories immediately. "
                "2. Store backups in secure, off-server locations with encrypted storage. "
                "3. Implement automated backup rotation with secure deletion of old backups. "
                "4. Verify that backup storage locations are never web-accessible. "
                "5. Use encrypted backups with keys stored separately from the backup data."
            ),
            'cwe_id': 'CWE-530',
            'cvss_score': 7.8
        })

    # Config directory -> A01:2021 Broken Access Control
    config_dirs = [d for d in found_dirs if d['path'] == '/config' and d.get('status') == 200]
    if config_dirs:
        vulnerabilities.append({
            'owasp_category': 'A01:2021',
            'title': 'Configuration Directory Exposed',
            'description': (
                "The /config directory is publicly accessible. Configuration files may contain "
                "database connection strings, API keys, internal service URLs, and other sensitive "
                "application settings that should not be exposed to unauthorized users."
            ),
            'severity': 'High',
            'affected_endpoint': '/config',
            'remediation': (
                "1. Deny web access to the /config directory via server configuration. "
                "2. Move configuration files outside the web root directory. "
                "3. Use environment variables or a secure vault for sensitive configuration values. "
                "4. Implement proper access controls for any configuration management interfaces."
            ),
            'cwe_id': 'CWE-538',
            'cvss_score': 7.5
        })

    return vulnerabilities

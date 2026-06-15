"""
Simulated scanning engine for CyberGuard AI.
All results are deterministically generated from the URL hash — no actual network requests.
"""

import hashlib
import random
from urllib.parse import urlparse


def _get_rng(url):
    """Create a seeded random.Random instance from the URL hash for deterministic output."""
    hash_hex = hashlib.md5(url.encode()).hexdigest()
    seed = int(hash_hex, 16)
    return random.Random(seed)


def run_full_scan(url):
    """Orchestrates all scan phases. Returns complete scan results dict."""
    results = {
        'port_results': simulate_port_scan(url),
        'ssl_results': simulate_ssl_check(url),
        'header_results': simulate_header_analysis(url),
        'directory_results': simulate_directory_discovery(url)
    }
    return results


def simulate_port_scan(url):
    """
    Simulate a port scan returning 5-15 port entries.
    Each entry: {port, service, version, state}
    """
    rng = _get_rng(url + ':ports')

    port_definitions = {
        21: {'service': 'FTP', 'versions': ['vsftpd 3.0.3', 'vsftpd 3.0.5', 'ProFTPD 1.3.5', 'Pure-FTPd 1.0.50']},
        22: {'service': 'SSH', 'versions': ['OpenSSH 7.4', 'OpenSSH 8.2p1', 'OpenSSH 8.9', 'OpenSSH 9.1', 'OpenSSH 9.3']},
        53: {'service': 'DNS', 'versions': ['BIND 9.16.1', 'BIND 9.18.12', 'dnsmasq 2.89']},
        80: {'service': 'HTTP', 'versions': ['Apache/2.4.41', 'Apache/2.4.52', 'Apache/2.4.57', 'Nginx/1.22.1', 'Nginx/1.24.0']},
        443: {'service': 'HTTPS', 'versions': ['Apache/2.4.41', 'Apache/2.4.52', 'Apache/2.4.57', 'Nginx/1.22.1', 'Nginx/1.24.0']},
        3306: {'service': 'MySQL', 'versions': ['MySQL 5.7.42', 'MySQL 8.0.28', 'MySQL 8.0.32', 'MariaDB 10.11.2']},
        5432: {'service': 'PostgreSQL', 'versions': ['PostgreSQL 12.4', 'PostgreSQL 14.8', 'PostgreSQL 15.3']},
        8080: {'service': 'HTTP-Proxy', 'versions': ['Nginx/1.21.6', 'Tomcat/9.0.65', 'Node.js/18.17.0', 'Jetty/11.0.15']},
        8443: {'service': 'HTTPS-Alt', 'versions': ['Tomcat/9.0.65', 'Jetty/11.0.15', 'WildFly/27.0.1']},
        6379: {'service': 'Redis', 'versions': ['Redis 6.2.12', 'Redis 7.0.11', 'Redis 7.2.0']},
        27017: {'service': 'MongoDB', 'versions': ['MongoDB 5.0.18', 'MongoDB 6.0.8', 'MongoDB 7.0.2']},
        9200: {'service': 'Elasticsearch', 'versions': ['Elasticsearch 7.17.12', 'Elasticsearch 8.9.1']},
        25: {'service': 'SMTP', 'versions': ['Postfix 3.7.4', 'Exim 4.96']},
        110: {'service': 'POP3', 'versions': ['Dovecot 2.3.19', 'Courier-POP3 5.2.1']},
        143: {'service': 'IMAP', 'versions': ['Dovecot 2.3.19', 'Cyrus IMAP 3.8.1']}
    }

    # Always include HTTP (80) and HTTPS (443)
    all_ports = list(port_definitions.keys())
    mandatory_ports = [80, 443]
    optional_ports = [p for p in all_ports if p not in mandatory_ports]

    num_extra = rng.randint(3, 13)
    selected_optional = rng.sample(optional_ports, min(num_extra, len(optional_ports)))
    selected_ports = sorted(set(mandatory_ports + selected_optional))

    results = []
    for port in selected_ports:
        pdef = port_definitions[port]
        state = 'open' if rng.random() > 0.2 else 'filtered'
        version = rng.choice(pdef['versions'])
        results.append({
            'port': port,
            'service': pdef['service'],
            'version': version,
            'state': state
        })

    return results


def simulate_ssl_check(url):
    """
    Simulate an SSL/TLS check.
    Returns: {valid, issuer, expiry, cipher_strength, grade, protocol, key_size}
    """
    rng = _get_rng(url + ':ssl')

    issuers = ['Let\'s Encrypt', 'DigiCert', 'Sectigo', 'Comodo CA', 'GlobalSign',
               'GeoTrust', 'Entrust', 'Amazon Trust Services']

    grades = ['A+', 'A', 'A', 'B', 'B', 'C', 'D', 'F']
    grade = rng.choice(grades)

    grade_config = {
        'A+': {'cipher': 'strong', 'protocol': 'TLSv1.3', 'key_size': 4096, 'valid': True},
        'A':  {'cipher': 'strong', 'protocol': 'TLSv1.3', 'key_size': 2048, 'valid': True},
        'B':  {'cipher': 'moderate', 'protocol': 'TLSv1.2', 'key_size': 2048, 'valid': True},
        'C':  {'cipher': 'moderate', 'protocol': 'TLSv1.2', 'key_size': 2048, 'valid': True},
        'D':  {'cipher': 'weak', 'protocol': 'TLSv1.1', 'key_size': 1024, 'valid': True},
        'F':  {'cipher': 'weak', 'protocol': 'TLSv1.0', 'key_size': 1024, 'valid': False}
    }

    cfg = grade_config[grade]

    # Generate expiry date 1-24 months from a reference date
    months_ahead = rng.randint(1, 24)
    expiry_year = 2026 + (6 + months_ahead) // 12
    expiry_month = (6 + months_ahead) % 12 or 12
    expiry = f"{expiry_year}-{expiry_month:02d}-{rng.randint(1, 28):02d}"

    return {
        'valid': cfg['valid'],
        'issuer': rng.choice(issuers),
        'expiry': expiry,
        'cipher_strength': cfg['cipher'],
        'grade': grade,
        'protocol': cfg['protocol'],
        'key_size': cfg['key_size']
    }


def simulate_header_analysis(url):
    """
    Simulate security header analysis for 7 critical headers.
    Each: {header, present, value, status, recommendation}
    """
    rng = _get_rng(url + ':headers')

    headers_config = [
        {
            'header': 'X-Frame-Options',
            'values': ['DENY', 'SAMEORIGIN'],
            'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking attacks.'
        },
        {
            'header': 'Content-Security-Policy',
            'values': ["default-src 'self'", "default-src 'self'; script-src 'self'",
                       "default-src 'self'; script-src 'self' 'unsafe-inline'"],
            'recommendation': 'Implement a Content-Security-Policy header to prevent XSS and data injection attacks.'
        },
        {
            'header': 'Strict-Transport-Security',
            'values': ['max-age=31536000', 'max-age=63072000; includeSubDomains; preload',
                       'max-age=15768000'],
            'recommendation': 'Enable HSTS with a minimum max-age of 31536000 seconds and include subdomains.'
        },
        {
            'header': 'X-XSS-Protection',
            'values': ['1; mode=block'],
            'recommendation': 'Set X-XSS-Protection to "1; mode=block" to enable browser XSS filtering.'
        },
        {
            'header': 'X-Content-Type-Options',
            'values': ['nosniff'],
            'recommendation': 'Set X-Content-Type-Options to "nosniff" to prevent MIME-type sniffing.'
        },
        {
            'header': 'Referrer-Policy',
            'values': ['no-referrer', 'strict-origin-when-cross-origin', 'same-origin'],
            'recommendation': 'Set Referrer-Policy to control information leakage through the Referer header.'
        },
        {
            'header': 'Permissions-Policy',
            'values': ['geolocation=(), camera=(), microphone=()',
                       'geolocation=(), camera=(), microphone=(), payment=(self)'],
            'recommendation': 'Set Permissions-Policy to restrict access to browser features like camera and geolocation.'
        }
    ]

    results = []
    for hdr in headers_config:
        present = rng.random() > 0.35  # ~65% chance of being present
        if present:
            value = rng.choice(hdr['values'])
            # Determine status based on header value quality
            if hdr['header'] == 'Strict-Transport-Security' and 'max-age=15768000' in value:
                status = 'warning'
            else:
                status = 'pass'
        else:
            value = None
            status = 'fail'

        results.append({
            'header': hdr['header'],
            'present': present,
            'value': value,
            'status': status,
            'recommendation': hdr['recommendation'] if not present else 'Header is properly configured.'
        })

    return results


def simulate_directory_discovery(url):
    """
    Simulate directory/path discovery for common sensitive paths.
    Each: {path, status, found, risk}
    """
    rng = _get_rng(url + ':dirs')

    paths_config = [
        {'path': '/admin', 'risk_if_found': 'high', 'common_statuses': [200, 301, 403]},
        {'path': '/login', 'risk_if_found': 'low', 'common_statuses': [200, 301]},
        {'path': '/backup', 'risk_if_found': 'high', 'common_statuses': [200, 403]},
        {'path': '/uploads', 'risk_if_found': 'medium', 'common_statuses': [200, 403]},
        {'path': '/config', 'risk_if_found': 'high', 'common_statuses': [200, 403]},
        {'path': '/api', 'risk_if_found': 'low', 'common_statuses': [200, 301]},
        {'path': '/debug', 'risk_if_found': 'high', 'common_statuses': [200, 403]},
        {'path': '/phpinfo', 'risk_if_found': 'high', 'common_statuses': [200]},
        {'path': '/.env', 'risk_if_found': 'high', 'common_statuses': [200]},
        {'path': '/.git', 'risk_if_found': 'high', 'common_statuses': [200, 403]}
    ]

    results = []
    for p in paths_config:
        # Probability of being found varies by path sensitivity
        if p['path'] in ['/login', '/api']:
            found = rng.random() > 0.2  # Usually found
        elif p['path'] in ['/.env', '/.git', '/debug', '/phpinfo']:
            found = rng.random() > 0.65  # Less commonly found
        else:
            found = rng.random() > 0.45  # Medium probability

        if found:
            status = rng.choice(p['common_statuses'])
            # Risk depends on status: 200 is riskiest, 403 is lower risk
            if status == 200:
                risk = p['risk_if_found']
            elif status == 301:
                risk = 'medium' if p['risk_if_found'] == 'high' else p['risk_if_found']
            else:  # 403
                risk = 'low'
        else:
            status = 404
            risk = 'none'

        results.append({
            'path': p['path'],
            'status': status,
            'found': found,
            'risk': risk
        })

    return results

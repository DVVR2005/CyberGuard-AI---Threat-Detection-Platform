"""
Threat Intelligence service for CyberGuard AI.
Provides mock CVE data, domain reputation checks, and global threat status.
"""

import hashlib
import random
from datetime import datetime, timedelta


def get_latest_cves(limit=20):
    """
    Returns mock CVE data. 20 realistic CVE entries with mix of severities.
    """
    cves = [
        {
            'cve_id': 'CVE-2024-21762',
            'title': 'Fortinet FortiOS Out-of-Bound Write Vulnerability',
            'description': 'An out-of-bounds write vulnerability in Fortinet FortiOS allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests. This vulnerability has been actively exploited in the wild.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-02-08',
            'affected_products': ['FortiOS 7.4.0-7.4.2', 'FortiOS 7.2.0-7.2.6', 'FortiOS 7.0.0-7.0.13'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-21762']
        },
        {
            'cve_id': 'CVE-2024-3094',
            'title': 'XZ Utils Backdoor - Supply Chain Compromise',
            'description': 'Malicious code was discovered in the upstream tarballs of xz starting from version 5.6.0. The backdoor manipulates the build process to inject code into the resulting liblzma library, enabling unauthorized SSH access.',
            'severity': 'Critical',
            'cvss_score': 10.0,
            'published_date': '2024-03-29',
            'affected_products': ['XZ Utils 5.6.0', 'XZ Utils 5.6.1'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094']
        },
        {
            'cve_id': 'CVE-2024-27198',
            'title': 'JetBrains TeamCity Authentication Bypass',
            'description': 'An authentication bypass vulnerability in JetBrains TeamCity before 2023.11.4 allows an unauthenticated attacker to gain administrative control of the TeamCity server via a specially crafted request.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-03-04',
            'affected_products': ['TeamCity < 2023.11.4'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-27198']
        },
        {
            'cve_id': 'CVE-2024-1709',
            'title': 'ConnectWise ScreenConnect Authentication Bypass',
            'description': 'An authentication bypass vulnerability in ConnectWise ScreenConnect 23.9.7 and prior allows an attacker to create administrative users, delete users, and execute remote code on affected systems.',
            'severity': 'Critical',
            'cvss_score': 10.0,
            'published_date': '2024-02-19',
            'affected_products': ['ScreenConnect <= 23.9.7'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-1709']
        },
        {
            'cve_id': 'CVE-2024-23897',
            'title': 'Jenkins CLI Arbitrary File Read Vulnerability',
            'description': 'Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that allows reading arbitrary files on the Jenkins controller file system.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-01-24',
            'affected_products': ['Jenkins <= 2.441', 'Jenkins LTS <= 2.426.2'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-23897']
        },
        {
            'cve_id': 'CVE-2024-4577',
            'title': 'PHP CGI Argument Injection Remote Code Execution',
            'description': 'In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, the system may allow an attacker to execute arbitrary code through argument injection.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-06-07',
            'affected_products': ['PHP 8.1.0-8.1.28', 'PHP 8.2.0-8.2.19', 'PHP 8.3.0-8.3.7'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-4577']
        },
        {
            'cve_id': 'CVE-2024-38077',
            'title': 'Windows Remote Desktop Licensing Service RCE',
            'description': 'A critical remote code execution vulnerability exists in the Windows Remote Desktop Licensing Service. An unauthenticated attacker could exploit this to execute arbitrary code on the target server.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-07-09',
            'affected_products': ['Windows Server 2012-2022', 'Windows Server 2019'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-38077']
        },
        {
            'cve_id': 'CVE-2024-6387',
            'title': 'OpenSSH regreSSHion - Remote Code Execution',
            'description': 'A signal handler race condition was found in OpenSSH sshd, where a client does not authenticate within LoginGraceTime seconds, leading to potential remote code execution with root privileges.',
            'severity': 'High',
            'cvss_score': 8.1,
            'published_date': '2024-07-01',
            'affected_products': ['OpenSSH 8.5p1-9.7p1'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-6387']
        },
        {
            'cve_id': 'CVE-2024-20353',
            'title': 'Cisco ASA and FTD Denial of Service Vulnerability',
            'description': 'A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software allows an unauthenticated remote attacker to cause the device to reload.',
            'severity': 'High',
            'cvss_score': 8.6,
            'published_date': '2024-04-24',
            'affected_products': ['Cisco ASA Software', 'Cisco FTD Software'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-20353']
        },
        {
            'cve_id': 'CVE-2024-21413',
            'title': 'Microsoft Outlook Remote Code Execution',
            'description': 'A remote code execution vulnerability in Microsoft Outlook allows an attacker to bypass Office Protected View and open a file in editing mode rather than protected mode through a specially crafted link.',
            'severity': 'High',
            'cvss_score': 8.8,
            'published_date': '2024-02-13',
            'affected_products': ['Microsoft Office 2016-2021', 'Microsoft 365 Apps'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-21413']
        },
        {
            'cve_id': 'CVE-2024-29988',
            'title': 'Windows SmartScreen Prompt Security Feature Bypass',
            'description': 'A vulnerability in Microsoft Windows SmartScreen allows an attacker to bypass the SmartScreen security warning dialog by crafting a malicious file that evokes the bypass.',
            'severity': 'High',
            'cvss_score': 8.8,
            'published_date': '2024-04-09',
            'affected_products': ['Windows 10', 'Windows 11', 'Windows Server 2019-2022'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-29988']
        },
        {
            'cve_id': 'CVE-2024-30088',
            'title': 'Windows Kernel Elevation of Privilege Vulnerability',
            'description': 'An elevation of privilege vulnerability exists in the Windows Kernel. An attacker who successfully exploits this vulnerability could gain SYSTEM-level privileges on the affected system.',
            'severity': 'High',
            'cvss_score': 7.8,
            'published_date': '2024-06-11',
            'affected_products': ['Windows 10 21H2-22H2', 'Windows 11 21H2-23H2', 'Windows Server 2022'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-30088']
        },
        {
            'cve_id': 'CVE-2024-21893',
            'title': 'Ivanti Connect Secure SSRF Vulnerability',
            'description': 'A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure allows an attacker to access certain restricted resources without authentication.',
            'severity': 'High',
            'cvss_score': 8.2,
            'published_date': '2024-01-31',
            'affected_products': ['Ivanti Connect Secure 9.x-22.x', 'Ivanti Policy Secure 9.x-22.x'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-21893']
        },
        {
            'cve_id': 'CVE-2024-28255',
            'title': 'OpenMetadata Authentication Bypass',
            'description': 'OpenMetadata before version 1.2.4 contains an authentication bypass vulnerability that allows attackers to access authenticated endpoints without valid credentials via a path traversal technique.',
            'severity': 'Medium',
            'cvss_score': 6.5,
            'published_date': '2024-03-15',
            'affected_products': ['OpenMetadata < 1.2.4'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-28255']
        },
        {
            'cve_id': 'CVE-2024-22243',
            'title': 'Spring Framework URL Parsing Vulnerability',
            'description': 'The Spring Framework versions 6.1.x before 6.1.4 are vulnerable to open redirect or SSRF attacks when applications use UriComponentsBuilder to parse externally provided URLs.',
            'severity': 'Medium',
            'cvss_score': 6.1,
            'published_date': '2024-02-23',
            'affected_products': ['Spring Framework 6.1.0-6.1.3', 'Spring Framework 6.0.0-6.0.16'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-22243']
        },
        {
            'cve_id': 'CVE-2024-25600',
            'title': 'WordPress Bricks Builder RCE',
            'description': 'An unauthenticated remote code execution vulnerability in the Bricks Builder theme for WordPress allows attackers to execute arbitrary PHP code on the server through the REST API.',
            'severity': 'Critical',
            'cvss_score': 9.8,
            'published_date': '2024-02-13',
            'affected_products': ['Bricks Builder <= 1.9.6'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-25600']
        },
        {
            'cve_id': 'CVE-2024-31497',
            'title': 'PuTTY ECDSA Private Key Recovery',
            'description': 'In PuTTY 0.68 through 0.80, biased ECDSA nonce generation allows an attacker to recover a user\'s NIST P-521 secret key by observing a sequence of signed messages.',
            'severity': 'Medium',
            'cvss_score': 5.9,
            'published_date': '2024-04-15',
            'affected_products': ['PuTTY 0.68-0.80', 'FileZilla < 3.67.0', 'WinSCP < 6.3.3'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-31497']
        },
        {
            'cve_id': 'CVE-2024-22024',
            'title': 'Ivanti Connect Secure XXE Vulnerability',
            'description': 'An XML External Entity (XXE) vulnerability in the SAML component of Ivanti Connect Secure allows an unauthenticated attacker to access restricted internal resources.',
            'severity': 'Medium',
            'cvss_score': 6.3,
            'published_date': '2024-02-08',
            'affected_products': ['Ivanti Connect Secure 9.1R14.4-22.5R1.1'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-22024']
        },
        {
            'cve_id': 'CVE-2024-2961',
            'title': 'GNU C Library Buffer Overflow via iconv',
            'description': 'A buffer overflow was discovered in the iconv() function of the GNU C Library when converting strings to the ISO-2022-CN-EXT character set, potentially leading to application crashes or code execution.',
            'severity': 'Low',
            'cvss_score': 3.9,
            'published_date': '2024-04-17',
            'affected_products': ['glibc 2.39 and earlier'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-2961']
        },
        {
            'cve_id': 'CVE-2024-20359',
            'title': 'Cisco ASA Persistent Local Code Execution',
            'description': 'A vulnerability in a legacy capability of Cisco ASA Software allows an authenticated, local attacker to execute arbitrary code with root-level privileges that persists across reboots.',
            'severity': 'Low',
            'cvss_score': 3.8,
            'published_date': '2024-04-24',
            'affected_products': ['Cisco ASA Software', 'Cisco FTD Software'],
            'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-20359']
        }
    ]

    return cves[:limit]


def get_domain_reputation(domain):
    """
    Mock domain reputation check. Uses hash of domain for deterministic output.
    Returns dict with status, risk_score, blacklisted, details, and whois info.
    """
    hash_hex = hashlib.md5(domain.encode()).hexdigest()
    seed = int(hash_hex, 16)
    rng = random.Random(seed)

    # Determine risk level based on hash
    risk_value = rng.randint(0, 100)
    if risk_value < 60:
        status = 'Safe'
        risk_score = rng.randint(0, 25)
        blacklisted = False
        malware = False
        phishing = False
        spam = False
        reputation_score = rng.randint(75, 100)
    elif risk_value < 85:
        status = 'Suspicious'
        risk_score = rng.randint(26, 65)
        blacklisted = False
        malware = False
        phishing = rng.choice([True, False])
        spam = rng.choice([True, False])
        reputation_score = rng.randint(40, 74)
    else:
        status = 'Malicious'
        risk_score = rng.randint(66, 100)
        blacklisted = True
        malware = rng.choice([True, False])
        phishing = True
        spam = True
        reputation_score = rng.randint(0, 39)

    registrars = [
        'GoDaddy LLC', 'Namecheap Inc.', 'Cloudflare Inc.', 'Google Domains',
        'Amazon Registrar Inc.', 'Tucows Domains Inc.', 'NameSilo LLC',
        'OVH SAS', 'Gandi SAS', 'Dynadot LLC'
    ]

    countries = ['US', 'US', 'US', 'DE', 'GB', 'NL', 'CA', 'FR', 'SG', 'JP']

    # Generate deterministic creation date
    year = rng.randint(2015, 2024)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)

    analysis_date = datetime.now() - timedelta(hours=rng.randint(1, 48))

    return {
        'domain': domain,
        'status': status,
        'risk_score': risk_score,
        'blacklisted': blacklisted,
        'last_analysis': analysis_date.strftime('%Y-%m-%d %H:%M:%S'),
        'details': {
            'malware': malware,
            'phishing': phishing,
            'spam': spam,
            'reputation_score': reputation_score
        },
        'whois': {
            'registrar': rng.choice(registrars),
            'creation_date': f'{year}-{month:02d}-{day:02d}',
            'country': rng.choice(countries)
        }
    }


def get_global_threat_status():
    """
    Returns mock global threat level information.
    """
    return {
        'threat_level': 'Elevated',
        'active_threats': 1247,
        'recent_cves_count': 89,
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'top_threat_categories': [
            {'category': 'Ransomware', 'count': 342, 'trend': 'increasing'},
            {'category': 'Phishing Campaigns', 'count': 567, 'trend': 'stable'},
            {'category': 'DDoS Attacks', 'count': 270, 'trend': 'increasing'},
            {'category': 'Supply Chain Attacks', 'count': 45, 'trend': 'increasing'},
            {'category': 'Zero-Day Exploits', 'count': 23, 'trend': 'decreasing'},
            {'category': 'Credential Stuffing', 'count': 189, 'trend': 'stable'},
            {'category': 'Cryptojacking', 'count': 78, 'trend': 'decreasing'},
            {'category': 'IoT Botnet Activity', 'count': 134, 'trend': 'increasing'}
        ],
        'threat_summary': (
            'Global threat activity remains at an elevated level with ransomware operations '
            'continuing to target critical infrastructure and healthcare sectors. Supply chain '
            'attacks have shown a concerning upward trend, while coordinated phishing campaigns '
            'leveraging AI-generated content are becoming more sophisticated.'
        )
    }

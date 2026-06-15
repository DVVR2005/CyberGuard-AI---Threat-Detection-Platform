"""
MITRE ATT&CK Mapping service for CyberGuard AI.
Maps CWE IDs to MITRE ATT&CK tactics and techniques.
"""

# Static mapping dictionary from CWE ID to MITRE ATT&CK tactic and technique
CWE_MITRE_MAP = {
    'CWE-284': {
        'tactic_id': 'TA0001',
        'tactic_name': 'Initial Access',
        'technique_id': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'description': 'Attackers exploit vulnerabilities in public-facing services (e.g. exposed databases, Redis) to gain initial access.'
    },
    'CWE-200': {
        'tactic_id': 'TA0007',
        'tactic_name': 'Discovery',
        'technique_id': 'T1082',
        'technique_name': 'System Information Discovery',
        'description': 'Attackers gather detailed software version, environment files, or repository data to aid their target planning.'
    },
    'CWE-319': {
        'tactic_id': 'TA0006',
        'tactic_name': 'Credential Access',
        'technique_id': 'T1040',
        'technique_name': 'Network Sniffing',
        'description': 'Attackers sniff cleartext network transmissions (like unencrypted FTP) to intercept credentials.'
    },
    'CWE-326': {
        'tactic_id': 'TA0005',
        'tactic_name': 'Defense Evasion',
        'technique_id': 'T1553',
        'technique_name': 'Subvert Trust Controls',
        'description': 'Attackers bypass weak cryptographic protocols (like TLSv1.1) to decrypt communications or subvert verification mechanisms.'
    },
    'CWE-538': {
        'tactic_id': 'TA0007',
        'tactic_name': 'Discovery',
        'technique_id': 'T1083',
        'technique_name': 'File and Directory Discovery',
        'description': 'Attackers browse directory structures or config locations looking for credentials or source files.'
    },
    'CWE-530': {
        'tactic_id': 'TA0006',
        'tactic_name': 'Credential Access',
        'technique_id': 'T1552',
        'technique_name': 'Unsecured Credentials',
        'description': 'Attackers search exposed backup directories to retrieve plaintext configuration files containing system secrets.'
    },
    'CWE-693': {
        'tactic_id': 'TA0005',
        'tactic_name': 'Defense Evasion',
        'technique_id': 'T1562',
        'technique_name': 'Impair Defenses',
        'description': 'Missing security headers or filters allows attackers to bypass security mechanisms, execute scripting payloads, or bypass sandbox protections.'
    },
    'CWE-778': {
        'tactic_id': 'TA0005',
        'tactic_name': 'Defense Evasion',
        'technique_id': 'T1562.006',
        'technique_name': 'Impair Defenses: Indicator Blocking',
        'description': 'Insufficient logging makes detection and response difficult, allowing attackers to remain undetected.'
    },
    'CWE-295': {
        'tactic_id': 'TA0005',
        'tactic_name': 'Defense Evasion',
        'technique_id': 'T1553.004',
        'technique_name': 'Subvert Trust Controls: Install Root Certificate',
        'description': 'Invalid or expired SSL certificates facilitate Adversary-in-the-Middle (AiTM) scenarios that bypass integrity checks.'
    }
}


def get_mitre_mapping(cwe_id):
    """
    Look up MITRE ATT&CK tactic/technique details by CWE ID.
    Returns mapping dictionary or default value.
    """
    cwe_clean = (cwe_id or '').strip().upper()
    
    if cwe_clean in CWE_MITRE_MAP:
        return CWE_MITRE_MAP[cwe_clean]
        
    # Default fallback mapping
    return {
        'tactic_id': 'TA0040',
        'tactic_name': 'Impact',
        'technique_id': 'T1498',
        'technique_name': 'Network Denial of Service',
        'description': 'Other unidentified software errors that impact system integrity or availability.'
    }


def get_all_tactics():
    """Returns a list of all standard MITRE tactics for matrix rendering."""
    return [
        {'id': 'TA0001', 'name': 'Initial Access'},
        {'id': 'TA0002', 'name': 'Execution'},
        {'id': 'TA0005', 'name': 'Defense Evasion'},
        {'id': 'TA0006', 'name': 'Credential Access'},
        {'id': 'TA0007', 'name': 'Discovery'},
        {'id': 'TA0040', 'name': 'Impact'}
    ]

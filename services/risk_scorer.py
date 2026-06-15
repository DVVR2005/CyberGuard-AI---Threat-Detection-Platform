"""
AI Risk Scoring engine for CyberGuard AI.
Calculates risk scores based on scan data using a weighted formula approach.
"""

import json


def get_severity_level(score):
    """Map numerical risk score to severity level."""
    if score <= 20:
        return 'Low'
    if score <= 40:
        return 'Medium'
    if score <= 60:
        return 'High'
    return 'Critical'


def get_grade(score):
    """Map numerical risk score to letter grade."""
    if score <= 10:
        return 'A+'
    if score <= 20:
        return 'A'
    if score <= 40:
        return 'B'
    if score <= 60:
        return 'C'
    if score <= 80:
        return 'D'
    return 'F'


def calculate_risk_score(scan_results, vulnerabilities):
    """
    Calculates AI risk score based on scan data.
    
    Uses weighted formula:
      risk = 100 - (ssl_weight * ssl_score + header_weight * header_score)
             + port_penalty + vuln_penalty + dir_penalty
    Clamped to 0-100.
    
    Returns dict with risk_score, severity_level, grade, contributing_factors, ai_explanation.
    """
    # -------------------------------------------------------------------------
    # Feature Extraction
    # -------------------------------------------------------------------------
    port_results = scan_results.get('port_results', [])
    ssl_results = scan_results.get('ssl_results', {})
    header_results = scan_results.get('header_results', [])
    directory_results = scan_results.get('directory_results', [])

    # Count open ports
    open_ports = [p for p in port_results if p.get('state') == 'open']
    open_port_count = len(open_ports)

    # Vulnerability counts
    vuln_count = len(vulnerabilities)
    critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
    high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')

    # SSL score (0-100 based on grade)
    ssl_grade_map = {'A+': 100, 'A': 90, 'B': 70, 'C': 50, 'D': 30, 'F': 10}
    ssl_grade = ssl_results.get('grade', 'C')
    ssl_score = ssl_grade_map.get(ssl_grade, 50)

    # Header score (percentage of headers passing)
    total_headers = len(header_results) if header_results else 7
    passing_headers = sum(1 for h in header_results if h.get('status') == 'pass')
    header_score = (passing_headers / total_headers * 100) if total_headers > 0 else 0

    # Exposed directories count
    exposed_dirs = [d for d in directory_results if d.get('found', False) and d.get('risk') in ('high', 'medium')]
    exposed_dir_count = len(exposed_dirs)

    # Check for specific high-risk services
    has_db_ports = any(p['port'] in (3306, 5432, 27017) for p in open_ports)
    has_ftp = any(p['port'] == 21 for p in open_ports)
    has_redis = any(p['port'] == 6379 for p in open_ports)

    # -------------------------------------------------------------------------
    # Risk Score Calculation
    # -------------------------------------------------------------------------
    # Positive contributions (reduce risk)
    ssl_contribution = 0.20 * ssl_score       # Max -20 points
    header_contribution = 0.15 * header_score  # Max -15 points

    # Negative contributions (increase risk)
    port_penalty = open_port_count * 1.5       # 1.5 per open port
    vuln_penalty = vuln_count * 3              # 3 per vulnerability
    critical_penalty = critical_count * 8       # 8 extra per critical
    dir_penalty = exposed_dir_count * 4         # 4 per exposed directory

    # Additional penalties for high-risk services
    service_penalty = 0
    if has_db_ports:
        service_penalty += 5
    if has_ftp:
        service_penalty += 3
    if has_redis:
        service_penalty += 4

    risk_score = (100
                  - ssl_contribution
                  - header_contribution
                  + port_penalty
                  + vuln_penalty
                  + critical_penalty
                  + dir_penalty
                  + service_penalty)

    # Clamp to 0-100
    risk_score = round(max(0, min(100, risk_score)), 1)

    severity_level = get_severity_level(risk_score)
    grade = get_grade(risk_score)

    # -------------------------------------------------------------------------
    # Contributing Factors
    # -------------------------------------------------------------------------
    contributing_factors = []

    # SSL factor
    if ssl_score >= 90:
        contributing_factors.append({
            'factor': 'SSL/TLS Configuration',
            'impact': 'low',
            'detail': f'Strong SSL configuration with grade {ssl_grade} using {ssl_results.get("protocol", "TLS")}'
        })
    elif ssl_score >= 50:
        contributing_factors.append({
            'factor': 'SSL/TLS Configuration',
            'impact': 'medium',
            'detail': f'Moderate SSL configuration with grade {ssl_grade}; upgrade to TLSv1.3 recommended'
        })
    else:
        contributing_factors.append({
            'factor': 'SSL/TLS Configuration',
            'impact': 'high',
            'detail': f'Weak SSL configuration with grade {ssl_grade} using deprecated {ssl_results.get("protocol", "TLS")}'
        })

    # Header factor
    failing_headers = [h['header'] for h in header_results if h.get('status') == 'fail']
    if not failing_headers:
        contributing_factors.append({
            'factor': 'Security Headers',
            'impact': 'low',
            'detail': f'All {total_headers} security headers properly configured'
        })
    elif len(failing_headers) <= 2:
        contributing_factors.append({
            'factor': 'Security Headers',
            'impact': 'medium',
            'detail': f'{len(failing_headers)} of {total_headers} security headers missing: {", ".join(failing_headers)}'
        })
    else:
        contributing_factors.append({
            'factor': 'Security Headers',
            'impact': 'high',
            'detail': f'{len(failing_headers)} of {total_headers} security headers missing'
        })

    # Open ports factor
    if open_port_count <= 3:
        contributing_factors.append({
            'factor': 'Open Ports',
            'impact': 'low',
            'detail': f'{open_port_count} open ports with minimal attack surface'
        })
    elif open_port_count <= 6:
        db_note = ' including database services' if has_db_ports else ''
        contributing_factors.append({
            'factor': 'Open Ports',
            'impact': 'medium',
            'detail': f'{open_port_count} open ports{db_note}'
        })
    else:
        services = [f"{p['service']}" for p in open_ports[:5]]
        contributing_factors.append({
            'factor': 'Open Ports',
            'impact': 'high',
            'detail': f'{open_port_count} open ports including {", ".join(services)} and others'
        })

    # Vulnerability factor
    if vuln_count > 0:
        impact = 'high' if critical_count > 0 else ('medium' if high_count > 0 else 'low')
        contributing_factors.append({
            'factor': 'Vulnerabilities',
            'impact': impact,
            'detail': f'{vuln_count} vulnerabilities found ({critical_count} Critical, {high_count} High)'
        })

    # Directory exposure factor
    if exposed_dir_count > 0:
        high_risk_dirs = [d['path'] for d in exposed_dirs if d.get('risk') == 'high']
        contributing_factors.append({
            'factor': 'Directory Exposure',
            'impact': 'high' if high_risk_dirs else 'medium',
            'detail': f'{exposed_dir_count} sensitive directories exposed'
                      + (f' including {", ".join(high_risk_dirs[:3])}' if high_risk_dirs else '')
        })

    # -------------------------------------------------------------------------
    # AI Explanation
    # -------------------------------------------------------------------------
    ai_explanation = _generate_explanation(
        risk_score, severity_level, grade,
        open_port_count, vuln_count, critical_count, high_count,
        ssl_grade, ssl_score, header_score, total_headers,
        failing_headers, exposed_dir_count, exposed_dirs,
        has_db_ports, has_ftp, has_redis
    )

    return {
        'risk_score': risk_score,
        'severity_level': severity_level,
        'grade': grade,
        'contributing_factors': contributing_factors,
        'ai_explanation': ai_explanation
    }


def _generate_explanation(risk_score, severity_level, grade,
                          open_port_count, vuln_count, critical_count, high_count,
                          ssl_grade, ssl_score, header_score, total_headers,
                          failing_headers, exposed_dir_count, exposed_dirs,
                          has_db_ports, has_ftp, has_redis):
    """Generate a detailed AI analyst-style explanation of the risk assessment."""
    sentences = []

    # Opening assessment
    if risk_score <= 20:
        sentences.append(
            f"This target demonstrates an excellent security posture with a {severity_level} risk "
            f"score of {risk_score}, earning a grade of {grade}."
        )
    elif risk_score <= 40:
        sentences.append(
            f"The target presents a {severity_level} risk level with a score of {risk_score} "
            f"and a grade of {grade}, indicating a generally well-maintained security configuration "
            f"with room for improvement."
        )
    elif risk_score <= 60:
        sentences.append(
            f"The target has a {severity_level} risk score of {risk_score} ({grade} grade), "
            f"indicating several security areas that require attention to reduce the overall attack surface."
        )
    else:
        sentences.append(
            f"The target is in a {severity_level} risk state with a score of {risk_score} ({grade} grade), "
            f"indicating significant security deficiencies that require immediate remediation."
        )

    # SSL assessment
    if ssl_score >= 90:
        sentences.append(
            f"The SSL/TLS configuration is strong with an {ssl_grade} grade, providing robust encryption."
        )
    elif ssl_score >= 50:
        sentences.append(
            f"The SSL/TLS configuration scored a {ssl_grade} grade and should be upgraded to improve "
            f"cryptographic protections."
        )
    else:
        sentences.append(
            f"The weak SSL/TLS configuration with a {ssl_grade} grade is a major concern and "
            f"represents a critical attack vector for data interception."
        )

    # Vulnerability assessment
    if vuln_count > 0:
        if critical_count > 0:
            sentences.append(
                f"A total of {vuln_count} vulnerabilities were identified, including {critical_count} "
                f"Critical and {high_count} High severity findings that pose immediate risk."
            )
        elif high_count > 0:
            sentences.append(
                f"The scan identified {vuln_count} vulnerabilities with {high_count} rated as High "
                f"severity, warranting prompt remediation."
            )
        else:
            sentences.append(
                f"The {vuln_count} identified vulnerabilities are primarily Low to Medium severity, "
                f"representing manageable risks that should be addressed in regular maintenance cycles."
            )

    # Specific risks
    specific_risks = []
    if has_db_ports:
        specific_risks.append("exposed database services")
    if has_ftp:
        specific_risks.append("an active FTP service")
    if exposed_dir_count > 3:
        specific_risks.append(f"{exposed_dir_count} exposed directories")
    if len(failing_headers) > 3:
        specific_risks.append("significant security header gaps")

    if specific_risks:
        sentences.append(
            f"Notable concerns include {', '.join(specific_risks)}, which collectively "
            f"increase the likelihood of successful exploitation."
        )

    # Closing recommendation
    if risk_score <= 20:
        sentences.append(
            "Maintaining current security practices while implementing minor recommendations "
            "will further strengthen this already solid security posture."
        )
    elif risk_score <= 60:
        sentences.append(
            "Prioritizing the remediation of high-severity findings and strengthening the "
            "overall security configuration is recommended to improve the risk profile."
        )
    else:
        sentences.append(
            "Immediate action is required to address critical vulnerabilities and reduce the "
            "attack surface before this system can be considered secure for production use."
        )

    return ' '.join(sentences)

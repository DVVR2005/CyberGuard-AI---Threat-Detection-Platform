"""
PDF Report Generator for CyberGuard AI.
Generates professional security assessment reports using ReportLab.
"""

import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable


# =============================================================================
# Color Palette
# =============================================================================
DARK_BLUE = HexColor('#0f172a')
MEDIUM_BLUE = HexColor('#1e293b')
LIGHT_BLUE = HexColor('#334155')
CYAN = HexColor('#06b6d4')
RED = HexColor('#ef4444')
ORANGE = HexColor('#f97316')
YELLOW = HexColor('#eab308')
GREEN = HexColor('#10b981')
GRAY = HexColor('#94a3b8')
LIGHT_GRAY = HexColor('#e2e8f0')
WHITE = white
BLACK = black

SEVERITY_COLORS = {
    'Critical': RED,
    'High': ORANGE,
    'Medium': YELLOW,
    'Low': GREEN
}


# =============================================================================
# Custom Styles
# =============================================================================

def _get_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='ReportTitle',
        fontName='Helvetica-Bold',
        fontSize=28,
        textColor=CYAN,
        alignment=TA_CENTER,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name='ReportSubtitle',
        fontName='Helvetica',
        fontSize=14,
        textColor=GRAY,
        alignment=TA_CENTER,
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name='SectionTitle',
        fontName='Helvetica-Bold',
        fontSize=18,
        textColor=DARK_BLUE,
        spaceBefore=20,
        spaceAfter=10,
        borderPadding=(0, 0, 4, 0)
    ))

    styles.add(ParagraphStyle(
        name='SubSectionTitle',
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=MEDIUM_BLUE,
        spaceBefore=12,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name='BodyText2',
        fontName='Helvetica',
        fontSize=10,
        textColor=DARK_BLUE,
        alignment=TA_JUSTIFY,
        spaceAfter=8,
        leading=14
    ))

    styles.add(ParagraphStyle(
        name='GradeDisplay',
        fontName='Helvetica-Bold',
        fontSize=48,
        textColor=CYAN,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name='MetaLabel',
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=LIGHT_BLUE
    ))

    styles.add(ParagraphStyle(
        name='MetaValue',
        fontName='Helvetica',
        fontSize=10,
        textColor=DARK_BLUE
    ))

    styles.add(ParagraphStyle(
        name='SmallText',
        fontName='Helvetica',
        fontSize=8,
        textColor=GRAY,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name='FooterStyle',
        fontName='Helvetica',
        fontSize=8,
        textColor=GRAY,
        alignment=TA_CENTER
    ))

    return styles


# =============================================================================
# Header / Footer
# =============================================================================

def _header_footer(canvas, doc):
    """Add header and footer to each page."""
    canvas.saveState()

    # Header line
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(2)
    canvas.line(40, A4[1] - 40, A4[0] - 40, A4[1] - 40)

    # Header text
    canvas.setFont('Helvetica-Bold', 9)
    canvas.setFillColor(DARK_BLUE)
    canvas.drawString(40, A4[1] - 35, 'CyberGuard AI')

    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(GRAY)
    canvas.drawRightString(A4[0] - 40, A4[1] - 35, 'Security Assessment Report')

    # Footer
    canvas.setStrokeColor(LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(40, 40, A4[0] - 40, 40)

    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(GRAY)
    canvas.drawString(40, 25, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    canvas.drawCentredString(A4[0] / 2, 25, 'CONFIDENTIAL')
    canvas.drawRightString(A4[0] - 40, 25, f'Page {doc.page}')

    canvas.restoreState()


# =============================================================================
# Report Sections
# =============================================================================

def _build_title_page(elements, styles, scan_data, risk_score):
    """Build the title page with prominent target/domain display."""
    elements.append(Spacer(1, 1.2 * inch))

    elements.append(Paragraph('CyberGuard AI', styles['ReportTitle']))
    elements.append(Paragraph('Enterprise Security Assessment Report', styles['ReportSubtitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 0.3 * inch))

    # ── Prominent Target Banner ──────────────────────────────────
    target_url = scan_data.get('target_url', 'N/A')
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    domain_or_ip = parsed.netloc or target_url
    scheme = parsed.scheme.upper() if parsed.scheme else 'N/A'

    target_banner = [
        [Paragraph('<b>SCAN TARGET</b>', styles['MetaLabel'])],
        [Paragraph(f'<font size=16><b>{domain_or_ip}</b></font>', styles['BodyText2'])],
        [Paragraph(f'Full URL: {target_url}', styles['SmallText'])],
        [Paragraph(f'Protocol: {scheme}', styles['SmallText'])],
    ]
    banner_table = Table(target_banner, colWidths=[6 * inch])
    banner_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOX', (0, 0), (-1, -1), 3, CYAN),
        ('LINEBELOW', (0, 0), (-1, 0), 1, CYAN),
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f0f9ff')),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── Grade + Score side by side ───────────────────────────────
    grade = risk_score.get('grade', 'N/A') if risk_score else 'N/A'
    score = risk_score.get('risk_score', 0) if risk_score else 0
    severity = risk_score.get('severity_level', 'N/A') if risk_score else 'N/A'
    sev_color = RED if severity in ('Critical', 'High') else (YELLOW if severity == 'Medium' else GREEN)

    grade_data = [
        [Paragraph('<b>Overall Grade</b>', styles['MetaLabel']),
         Paragraph('<b>Risk Score</b>', styles['MetaLabel']),
         Paragraph('<b>Severity</b>', styles['MetaLabel'])],
        [Paragraph(grade, styles['GradeDisplay']),
         Paragraph(f'<font size=36><b>{score}</b></font><font size=14>/100</font>', styles['BodyText2']),
         Paragraph(f'<font size=18><b>{severity}</b></font>', styles['BodyText2'])],
    ]
    grade_table = Table(grade_data, colWidths=[2 * inch, 2 * inch, 2 * inch])
    grade_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 2, CYAN),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8fafc')),
        ('TEXTCOLOR', (2, 1), (2, 1), sev_color),
    ]))
    elements.append(grade_table)
    elements.append(Spacer(1, 0.3 * inch))

    # ── Full Metadata Table ──────────────────────────────────────
    scan_date = scan_data.get('completed_at', scan_data.get('created_at', 'N/A'))
    started_at = scan_data.get('started_at', 'N/A')
    scan_id = scan_data.get('id', 'N/A')
    scan_status = scan_data.get('status', 'N/A')

    meta_data = [
        ['Property', 'Value'],
        ['Scanned Target', target_url],
        ['Domain / IP', domain_or_ip],
        ['Protocol', scheme],
        ['Scan ID', str(scan_id)],
        ['Scan Type', scan_data.get('scan_type', 'Full').title()],
        ['Scan Status', scan_status.title()],
        ['Scan Started', started_at],
        ['Scan Completed', scan_date],
        ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
    ]
    meta_table = Table(meta_data, colWidths=[2.0 * inch, 4.0 * inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 1), (0, -1), LIGHT_BLUE),
        ('TEXTCOLOR', (1, 1), (1, -1), DARK_BLUE),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        # Highlight the domain row
        ('BACKGROUND', (1, 2), (1, 2), HexColor('#e0f2fe')),
        ('FONTNAME', (1, 2), (1, 2), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1, 2), (1, 2), DARK_BLUE),
    ]))
    elements.append(meta_table)

    elements.append(PageBreak())


def _build_executive_summary(elements, styles, scan_data, vulnerabilities, risk_score):
    """Build the executive summary section."""
    elements.append(Paragraph('1. Executive Summary', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    target_url = scan_data.get('target_url', 'the target')
    vuln_count = len(vulnerabilities) if vulnerabilities else 0
    critical_count = sum(1 for v in (vulnerabilities or []) if v.get('severity') == 'Critical')
    high_count = sum(1 for v in (vulnerabilities or []) if v.get('severity') == 'High')
    score = risk_score.get('risk_score', 0) if risk_score else 0
    grade = risk_score.get('grade', 'N/A') if risk_score else 'N/A'
    severity = risk_score.get('severity_level', 'N/A') if risk_score else 'N/A'

    para1 = (
        f'CyberGuard AI conducted a comprehensive security assessment of <b>{target_url}</b>. '
        f'The assessment covered port scanning, SSL/TLS analysis, security header verification, '
        f'directory discovery, and vulnerability classification against the OWASP Top 10 (2021) framework. '
        f'The overall risk score is <b>{score}/100</b> with a grade of <b>{grade}</b>, '
        f'indicating a <b>{severity}</b> risk level.'
    )
    elements.append(Paragraph(para1, styles['BodyText2']))

    para2 = (
        f'The assessment identified a total of <b>{vuln_count} vulnerabilities</b>, '
        f'including <b>{critical_count} Critical</b> and <b>{high_count} High</b> severity findings. '
    )
    if critical_count > 0:
        para2 += (
            'Critical findings require immediate attention as they represent exploitable weaknesses '
            'that could lead to unauthorized access, data breach, or system compromise.'
        )
    elif high_count > 0:
        para2 += (
            'High severity findings should be prioritized for remediation within the next sprint cycle '
            'to reduce the overall attack surface.'
        )
    else:
        para2 += (
            'The findings are primarily of moderate to low severity, suggesting a generally '
            'well-maintained security posture with opportunities for improvement.'
        )
    elements.append(Paragraph(para2, styles['BodyText2']))

    # Quick stats table
    stats_data = [
        ['Metric', 'Value'],
        ['Risk Score', f'{score}/100'],
        ['Grade', grade],
        ['Severity Level', severity],
        ['Total Vulnerabilities', str(vuln_count)],
        ['Critical Findings', str(critical_count)],
        ['High Findings', str(high_count)]
    ]
    stats_table = Table(stats_data, colWidths=[3 * inch, 3 * inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(Spacer(1, 10))
    elements.append(stats_table)


def _build_risk_assessment(elements, styles, risk_score):
    """Build the risk assessment section."""
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('2. Risk Assessment', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    if not risk_score:
        elements.append(Paragraph('No risk assessment data available.', styles['BodyText2']))
        return

    # AI Explanation
    explanation = risk_score.get('ai_explanation', '')
    if explanation:
        elements.append(Paragraph('<b>AI Analysis:</b>', styles['SubSectionTitle']))
        elements.append(Paragraph(explanation, styles['BodyText2']))

    # Contributing factors
    factors_raw = risk_score.get('contributing_factors', [])
    if isinstance(factors_raw, str):
        try:
            factors = json.loads(factors_raw)
        except (json.JSONDecodeError, TypeError):
            factors = []
    else:
        factors = factors_raw

    if factors:
        elements.append(Paragraph('<b>Contributing Factors:</b>', styles['SubSectionTitle']))
        factor_data = [['Factor', 'Impact', 'Detail']]
        for f in factors:
            impact = f.get('impact', 'medium').upper()
            factor_data.append([
                f.get('factor', 'N/A'),
                impact,
                f.get('detail', 'N/A')
            ])

        factor_table = Table(factor_data, colWidths=[1.5 * inch, 1 * inch, 3.5 * inch])
        factor_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(factor_table)


def _build_vulnerability_table(elements, styles, vulnerabilities):
    """Build the vulnerability findings summary table."""
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('3. Vulnerability Findings', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    if not vulnerabilities:
        elements.append(Paragraph('No vulnerabilities identified.', styles['BodyText2']))
        return

    elements.append(Paragraph(
        f'A total of <b>{len(vulnerabilities)}</b> vulnerabilities were identified during the assessment.',
        styles['BodyText2']
    ))

    # Summary table
    vuln_data = [['#', 'Category', 'Title', 'Severity', 'CVSS', 'Endpoint']]
    for idx, v in enumerate(vulnerabilities, 1):
        severity = v.get('severity', 'N/A')
        cvss = v.get('cvss_score', 0)
        title = v.get('title', 'N/A')
        # Truncate long titles
        if len(title) > 40:
            title = title[:37] + '...'
        endpoint = v.get('affected_endpoint', 'N/A')
        if len(str(endpoint)) > 20:
            endpoint = str(endpoint)[:17] + '...'

        vuln_data.append([
            str(idx),
            v.get('owasp_category', 'N/A'),
            title,
            severity,
            str(cvss),
            endpoint
        ])

    vuln_table = Table(vuln_data, colWidths=[0.4 * inch, 0.9 * inch, 2.0 * inch, 0.8 * inch, 0.5 * inch, 1.4 * inch])
    table_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('ALIGN', (4, 0), (4, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]

    # Color-code severity cells
    for idx, v in enumerate(vulnerabilities, 1):
        sev = v.get('severity', '')
        color = SEVERITY_COLORS.get(sev, GRAY)
        table_style.append(('TEXTCOLOR', (3, idx), (3, idx), color))
        table_style.append(('FONTNAME', (3, idx), (3, idx), 'Helvetica-Bold'))

    vuln_table.setStyle(TableStyle(table_style))
    elements.append(vuln_table)


def _build_detailed_findings(elements, styles, vulnerabilities):
    """Build detailed findings for each vulnerability."""
    elements.append(PageBreak())
    elements.append(Paragraph('4. Detailed Findings', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    if not vulnerabilities:
        elements.append(Paragraph('No detailed findings to report.', styles['BodyText2']))
        return

    for idx, v in enumerate(vulnerabilities, 1):
        severity = v.get('severity', 'N/A')
        sev_color = SEVERITY_COLORS.get(severity, GRAY)

        finding_header = (
            f'<b>Finding #{idx}: {v.get("title", "N/A")}</b>'
        )
        elements.append(Paragraph(finding_header, styles['SubSectionTitle']))

        # Metadata row
        meta = [
            ['Category', 'Severity', 'CVSS', 'CWE', 'Endpoint'],
            [
                v.get('owasp_category', 'N/A'),
                severity,
                str(v.get('cvss_score', 'N/A')),
                v.get('cwe_id', 'N/A'),
                v.get('affected_endpoint', 'N/A')
            ]
        ]
        meta_table = Table(meta, colWidths=[1.2 * inch, 1 * inch, 0.8 * inch, 1 * inch, 2 * inch])
        meta_style = [
            ('BACKGROUND', (0, 0), (-1, 0), LIGHT_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TEXTCOLOR', (1, 1), (1, 1), sev_color),
            ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
        ]
        meta_table.setStyle(TableStyle(meta_style))
        elements.append(meta_table)

        # Description
        elements.append(Paragraph('<b>Description:</b>', styles['MetaLabel']))
        elements.append(Paragraph(v.get('description', 'No description available.'), styles['BodyText2']))

        # Remediation
        elements.append(Paragraph('<b>Remediation:</b>', styles['MetaLabel']))
        elements.append(Paragraph(v.get('remediation', 'No remediation available.'), styles['BodyText2']))

        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width='100%', thickness=0.5, color=LIGHT_GRAY))


def _build_threat_intelligence(elements, styles, threat_data):
    """Build the threat intelligence section."""
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('5. Threat Intelligence', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    if not threat_data:
        elements.append(Paragraph('No threat intelligence data available for this scan.', styles['BodyText2']))
        return

    # Handle different formats of threat_data
    if isinstance(threat_data, list) and len(threat_data) > 0:
        feed = threat_data[0]
        raw = feed.get('threat_data', '{}')
        if isinstance(raw, str):
            try:
                reputation = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                reputation = {}
        else:
            reputation = raw
    elif isinstance(threat_data, dict):
        reputation = threat_data
    else:
        reputation = {}

    if reputation:
        domain = reputation.get('domain', 'N/A')
        status = reputation.get('status', 'N/A')
        risk = reputation.get('risk_score', 'N/A')

        elements.append(Paragraph(f'<b>Domain Reputation: {domain}</b>', styles['SubSectionTitle']))

        rep_data = [
            ['Property', 'Value'],
            ['Status', status],
            ['Risk Score', str(risk)],
            ['Blacklisted', str(reputation.get('blacklisted', 'N/A'))],
            ['Malware Detected', str(reputation.get('details', {}).get('malware', 'N/A'))],
            ['Phishing Detected', str(reputation.get('details', {}).get('phishing', 'N/A'))],
            ['Registrar', str(reputation.get('whois', {}).get('registrar', 'N/A'))],
            ['Country', str(reputation.get('whois', {}).get('country', 'N/A'))]
        ]
        rep_table = Table(rep_data, colWidths=[2.5 * inch, 3.5 * inch])
        rep_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(rep_table)


def _build_recommendations(elements, styles, vulnerabilities, risk_score):
    """Build the top 5 prioritized recommendations section."""
    elements.append(Spacer(1, 20))
    elements.append(Paragraph('6. Recommendations', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        'Based on the assessment findings, the following prioritized actions are recommended:',
        styles['BodyText2']
    ))

    # Generate recommendations from vulnerabilities
    recommendations = []
    if vulnerabilities:
        # Sort by CVSS score descending
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get('cvss_score', 0), reverse=True)
        seen_categories = set()

        for v in sorted_vulns:
            cat = v.get('owasp_category', '')
            if cat not in seen_categories and len(recommendations) < 5:
                seen_categories.add(cat)
                severity = v.get('severity', 'Medium')
                priority = 'CRITICAL' if severity == 'Critical' else (
                    'HIGH' if severity == 'High' else 'MEDIUM')
                recommendations.append({
                    'priority': priority,
                    'title': v.get('title', 'Address finding'),
                    'action': v.get('remediation', 'Review and remediate this finding.')
                })

    # Ensure at least 5 recommendations
    default_recs = [
        {'priority': 'HIGH', 'title': 'Implement Security Header Configuration',
         'action': 'Configure all recommended security headers (CSP, HSTS, X-Frame-Options, etc.) on all web servers.'},
        {'priority': 'MEDIUM', 'title': 'Establish Regular Vulnerability Scanning',
         'action': 'Schedule weekly automated vulnerability scans and quarterly manual penetration testing.'},
        {'priority': 'MEDIUM', 'title': 'Implement Security Monitoring and Alerting',
         'action': 'Deploy a SIEM solution and configure alerting for suspicious activities and security events.'},
        {'priority': 'LOW', 'title': 'Develop Incident Response Plan',
         'action': 'Create and test an incident response plan covering detection, containment, eradication, and recovery.'},
        {'priority': 'LOW', 'title': 'Conduct Security Awareness Training',
         'action': 'Implement regular security awareness training for all staff, focusing on phishing and social engineering.'}
    ]

    while len(recommendations) < 5:
        rec = default_recs[len(recommendations)]
        recommendations.append(rec)

    rec_data = [['Priority', '#', 'Recommendation', 'Action Required']]
    for idx, rec in enumerate(recommendations, 1):
        rec_data.append([
            rec['priority'],
            str(idx),
            rec['title'][:50],
            rec['action'][:80] + ('...' if len(rec['action']) > 80 else '')
        ])

    rec_table = Table(rec_data, colWidths=[0.8 * inch, 0.4 * inch, 2.0 * inch, 2.8 * inch])
    rec_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (1, -1), 'CENTER'),
    ]

    # Color priority cells
    for idx in range(1, len(rec_data)):
        priority = rec_data[idx][0]
        if priority == 'CRITICAL':
            rec_style.append(('TEXTCOLOR', (0, idx), (0, idx), RED))
        elif priority == 'HIGH':
            rec_style.append(('TEXTCOLOR', (0, idx), (0, idx), ORANGE))
        elif priority == 'MEDIUM':
            rec_style.append(('TEXTCOLOR', (0, idx), (0, idx), YELLOW))
        rec_style.append(('FONTNAME', (0, idx), (0, idx), 'Helvetica-Bold'))

    rec_table.setStyle(TableStyle(rec_style))
    elements.append(rec_table)


def _build_port_scan_section(elements, styles, scan_data):
    """Build a detailed Port Scan Results section."""
    port_results = scan_data.get('port_results', [])
    if isinstance(port_results, str):
        try:
            port_results = json.loads(port_results)
        except Exception:
            port_results = []

    elements.append(Spacer(1, 20))
    elements.append(Paragraph('8. Port Scan Results', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    target_url = scan_data.get('target_url', 'N/A')
    from urllib.parse import urlparse
    domain_or_ip = urlparse(target_url).netloc or target_url

    elements.append(Paragraph(
        f'Port scan results for target: <b>{domain_or_ip}</b>. '
        'Identifies open services and their versions to map the attack surface.',
        styles['BodyText2']
    ))

    if not port_results:
        elements.append(Paragraph('No open ports detected or port scan data unavailable.', styles['BodyText2']))
        return

    open_ports = [p for p in port_results if str(p.get('state', '')).lower() == 'open']
    elements.append(Paragraph(
        f'Total ports scanned: <b>{len(port_results)}</b> | Open ports found: <b>{len(open_ports)}</b>',
        styles['BodyText2']
    ))

    port_data = [['Port', 'Protocol', 'Service', 'Version / Banner', 'State', 'Risk']]
    for p in port_results:
        state = str(p.get('state', 'unknown')).lower()
        service = str(p.get('service', 'Unknown'))
        risk = 'High' if p.get('port') in (21, 23, 3389, 445, 139) else (
               'Medium' if p.get('port') in (80, 8080, 8443) else 'Low')
        port_data.append([
            str(p.get('port', 'N/A')),
            str(p.get('protocol', 'tcp')).upper(),
            service,
            str(p.get('version', '') or p.get('banner', '') or 'N/A')[:40],
            state.title(),
            risk
        ])

    port_table = Table(port_data, colWidths=[0.6*inch, 0.7*inch, 1.2*inch, 2.1*inch, 0.7*inch, 0.7*inch])
    pt_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ALIGN', (0, 0), (1, -1), 'CENTER'),
        ('ALIGN', (4, 0), (5, -1), 'CENTER'),
    ]
    for i, row in enumerate(port_data[1:], 1):
        risk_val = row[5]
        if risk_val == 'High':
            pt_style.append(('TEXTCOLOR', (5, i), (5, i), RED))
            pt_style.append(('FONTNAME', (5, i), (5, i), 'Helvetica-Bold'))
        elif risk_val == 'Medium':
            pt_style.append(('TEXTCOLOR', (5, i), (5, i), ORANGE))
        state_val = row[4].lower()
        if state_val == 'open':
            pt_style.append(('TEXTCOLOR', (4, i), (4, i), GREEN))
            pt_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))
    port_table.setStyle(TableStyle(pt_style))
    elements.append(port_table)


def _build_ssl_section(elements, styles, scan_data):
    """Build a detailed SSL/TLS Certificate Analysis section."""
    ssl_results = scan_data.get('ssl_results', {})
    if isinstance(ssl_results, str):
        try:
            ssl_results = json.loads(ssl_results)
        except Exception:
            ssl_results = {}

    elements.append(Spacer(1, 20))
    elements.append(Paragraph('9. SSL/TLS Certificate Analysis', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    target_url = scan_data.get('target_url', 'N/A')
    from urllib.parse import urlparse
    domain_or_ip = urlparse(target_url).netloc or target_url

    elements.append(Paragraph(
        f'SSL/TLS encryption analysis for <b>{domain_or_ip}</b>. '
        'Evaluates certificate validity, cipher strength, protocol versions, and expiry.',
        styles['BodyText2']
    ))

    if not ssl_results:
        elements.append(Paragraph('No SSL/TLS data available. Target may not support HTTPS.', styles['BodyText2']))
        return

    grade = ssl_results.get('grade', 'N/A')
    valid = ssl_results.get('valid', False)
    issuer = ssl_results.get('issuer', 'N/A')
    expiry = ssl_results.get('expiry') or ssl_results.get('expires') or 'N/A'
    protocol = ssl_results.get('protocol', 'N/A')
    cipher = ssl_results.get('cipher', 'N/A')
    key_size = ssl_results.get('key_size', 'N/A')
    subject = ssl_results.get('subject') or domain_or_ip
    san = ssl_results.get('san', ssl_results.get('subject_alt_names', 'N/A'))
    if isinstance(san, list):
        san = ', '.join(san)

    ssl_data = [
        ['Property', 'Value', 'Status'],
        ['SSL Grade', grade, 'Good' if grade in ('A+', 'A', 'A-') else ('Fair' if grade == 'B' else 'Poor')],
        ['Certificate Valid', 'Yes' if valid else 'No', 'Pass' if valid else 'FAIL'],
        ['Subject (CN)', str(subject), 'Info'],
        ['Issuer / CA', str(issuer), 'Info'],
        ['Expiry Date', str(expiry), 'Info'],
        ['TLS Protocol', str(protocol), 'Good' if 'TLS 1.3' in str(protocol) or 'TLS 1.2' in str(protocol) else 'FAIL'],
        ['Cipher Suite', str(cipher)[:50], 'Info'],
        ['Key Size (bits)', str(key_size), 'Good' if str(key_size) in ('2048', '3072', '4096') else 'Warn'],
        ['Alt Names (SAN)', str(san)[:60], 'Info'],
    ]

    ssl_table = Table(ssl_data, colWidths=[1.8*inch, 3.2*inch, 1.0*inch])
    ssl_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 1), (0, -1), LIGHT_BLUE),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
    ]
    status_colors = {'Pass': GREEN, 'Good': GREEN, 'FAIL': RED, 'Poor': RED, 'Warn': ORANGE, 'Fair': YELLOW}
    for i, row in enumerate(ssl_data[1:], 1):
        st = row[2]
        col = status_colors.get(st, GRAY)
        ssl_style.append(('TEXTCOLOR', (2, i), (2, i), col))
        ssl_style.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))
    ssl_table.setStyle(TableStyle(ssl_style))
    elements.append(ssl_table)

    # Warnings
    warnings = ssl_results.get('warnings', [])
    if warnings:
        elements.append(Spacer(1, 8))
        elements.append(Paragraph('<b>SSL Warnings:</b>', styles['MetaLabel']))
        for w in warnings:
            elements.append(Paragraph(f'• {w}', styles['BodyText2']))


def _build_headers_section(elements, styles, scan_data):
    """Build a detailed Security Headers Analysis section."""
    header_results = scan_data.get('header_results', [])
    if isinstance(header_results, str):
        try:
            header_results = json.loads(header_results)
        except Exception:
            header_results = []

    elements.append(Spacer(1, 20))
    elements.append(Paragraph('10. Security Headers Analysis', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    target_url = scan_data.get('target_url', 'N/A')
    from urllib.parse import urlparse
    domain_or_ip = urlparse(target_url).netloc or target_url

    elements.append(Paragraph(
        f'HTTP security header analysis for <b>{domain_or_ip}</b>. '
        'Missing or misconfigured headers are a common attack vector for XSS, clickjacking, and MITM attacks.',
        styles['BodyText2']
    ))

    if not header_results:
        elements.append(Paragraph('No security header data available.', styles['BodyText2']))
        return

    pass_count = sum(1 for h in header_results if (h.get('status', '') or ('pass' if h.get('present') else 'fail')).lower() == 'pass')
    fail_count = len(header_results) - pass_count
    elements.append(Paragraph(
        f'Headers checked: <b>{len(header_results)}</b> | Passed: <b>{pass_count}</b> | Failed/Missing: <b>{fail_count}</b>',
        styles['BodyText2']
    ))

    hdr_data = [['Security Header', 'Status', 'Current Value', 'Recommendation']]
    for h in header_results:
        name = h.get('header') or h.get('name', 'N/A')
        raw_status = h.get('status', '')
        if not raw_status:
            raw_status = 'pass' if h.get('present') else 'fail'
        status = raw_status.upper()
        value = str(h.get('value', 'Not Set'))[:35] or 'Not Set'
        rec = str(h.get('recommendation') or h.get('description', ''))[:55]
        hdr_data.append([name, status, value, rec])

    hdr_table = Table(hdr_data, colWidths=[1.8*inch, 0.7*inch, 1.8*inch, 1.7*inch])
    hdr_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]
    for i, row in enumerate(hdr_data[1:], 1):
        st = row[1].lower()
        if st == 'pass':
            hdr_style.append(('TEXTCOLOR', (1, i), (1, i), GREEN))
        elif st == 'fail':
            hdr_style.append(('TEXTCOLOR', (1, i), (1, i), RED))
        else:
            hdr_style.append(('TEXTCOLOR', (1, i), (1, i), YELLOW))
        hdr_style.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))
    hdr_table.setStyle(TableStyle(hdr_style))
    elements.append(hdr_table)


def _build_directory_section(elements, styles, scan_data):
    """Build a detailed Directory Discovery section."""
    dir_results = scan_data.get('directory_results', [])
    if isinstance(dir_results, str):
        try:
            dir_results = json.loads(dir_results)
        except Exception:
            dir_results = []

    elements.append(Spacer(1, 20))
    elements.append(Paragraph('11. Directory & Path Discovery', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    target_url = scan_data.get('target_url', 'N/A')
    from urllib.parse import urlparse
    domain_or_ip = urlparse(target_url).netloc or target_url

    elements.append(Paragraph(
        f'Directory and file discovery results for <b>{domain_or_ip}</b>. '
        'Exposed paths may reveal admin panels, configuration files, backups, or sensitive resources.',
        styles['BodyText2']
    ))

    if not dir_results:
        elements.append(Paragraph('No directory scan data available or no accessible paths found.', styles['BodyText2']))
        return

    high_risk = [d for d in dir_results if str(d.get('risk') or d.get('risk_level', '')).lower() == 'high']
    elements.append(Paragraph(
        f'Paths discovered: <b>{len(dir_results)}</b> | High-risk paths: <b>{len(high_risk)}</b>',
        styles['BodyText2']
    ))

    dir_data = [['Path', 'HTTP Status', 'Content Size', 'Risk Level', 'Notes']]
    for d in dir_results:
        risk = str(d.get('risk') or d.get('risk_level', 'none')).lower()
        path = str(d.get('path', 'N/A'))
        status = str(d.get('status_code') or d.get('status', 'N/A'))
        size = str(d.get('size') or d.get('content_length', 'N/A'))
        notes = str(d.get('notes') or d.get('description', ''))
        if not notes:
            if risk == 'high':
                notes = 'Sensitive path — review access control'
            elif risk == 'medium':
                notes = 'Restrict access if not public'
            else:
                notes = 'Accessible'
        dir_data.append([path[:40], status, size, risk.title(), notes[:40]])

    dir_table = Table(dir_data, colWidths=[2.0*inch, 0.8*inch, 0.9*inch, 0.8*inch, 1.5*inch])
    dir_style = [
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ALIGN', (1, 0), (3, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (0, -1), 'Courier'),
    ]
    for i, row in enumerate(dir_data[1:], 1):
        risk_val = row[3].lower()
        if risk_val == 'high':
            dir_style.append(('TEXTCOLOR', (3, i), (3, i), RED))
            dir_style.append(('FONTNAME', (3, i), (3, i), 'Helvetica-Bold'))
        elif risk_val == 'medium':
            dir_style.append(('TEXTCOLOR', (3, i), (3, i), ORANGE))
        elif risk_val == 'low':
            dir_style.append(('TEXTCOLOR', (3, i), (3, i), GREEN))
    dir_table.setStyle(TableStyle(dir_style))
    elements.append(dir_table)


def _build_appendix(elements, styles, scan_data):
    """Build the appendix with scan metadata and methodology."""
    elements.append(PageBreak())
    elements.append(Paragraph('7. Appendix', styles['SectionTitle']))
    elements.append(HRFlowable(width='100%', thickness=2, color=CYAN))
    elements.append(Spacer(1, 10))

    # Scan Metadata
    elements.append(Paragraph('<b>A. Scan Metadata</b>', styles['SubSectionTitle']))
    meta_items = [
        ['Property', 'Value'],
        ['Target URL', scan_data.get('target_url', 'N/A')],
        ['Scan Type', scan_data.get('scan_type', 'Full')],
        ['Status', scan_data.get('status', 'N/A')],
        ['Started At', scan_data.get('started_at', 'N/A')],
        ['Completed At', scan_data.get('completed_at', 'N/A')],
        ['Scan ID', str(scan_data.get('id', 'N/A'))],
    ]
    meta_table = Table(meta_items, colWidths=[2 * inch, 4 * inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), LIGHT_BLUE),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, LIGHT_GRAY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 15))

    # Methodology
    elements.append(Paragraph('<b>B. Methodology</b>', styles['SubSectionTitle']))
    methodology = (
        'This security assessment was conducted using CyberGuard AI\'s automated scanning engine. '
        'The assessment methodology includes the following phases: '
        '<b>1) Reconnaissance</b> - Port scanning and service enumeration to identify the attack surface. '
        '<b>2) SSL/TLS Analysis</b> - Evaluation of encryption configuration, certificate validity, and cipher strength. '
        '<b>3) Security Header Analysis</b> - Verification of HTTP security headers against industry best practices. '
        '<b>4) Directory Discovery</b> - Probing for sensitive directories, configuration files, and exposed resources. '
        '<b>5) OWASP Classification</b> - Mapping findings to the OWASP Top 10 (2021) vulnerability categories. '
        '<b>6) AI Risk Scoring</b> - Calculating a composite risk score using weighted analysis of all findings.'
    )
    elements.append(Paragraph(methodology, styles['BodyText2']))

    elements.append(Spacer(1, 15))

    # Disclaimer
    elements.append(Paragraph('<b>C. Disclaimer</b>', styles['SubSectionTitle']))
    disclaimer = (
        'This report is generated by CyberGuard AI\'s automated security assessment platform and is intended '
        'for informational purposes only. The findings are based on simulated scanning techniques and should '
        'be validated through manual security testing. This report does not guarantee the absence of additional '
        'vulnerabilities not detected by automated scanning. Organizations should complement automated assessments '
        'with regular manual penetration testing and code review.'
    )
    elements.append(Paragraph(disclaimer, styles['BodyText2']))


# =============================================================================
# Main Report Generator
# =============================================================================

def generate_report(scan_data, vulnerabilities, risk_score, threat_data, output_path):
    """
    Generates a professional PDF security assessment report.
    
    Args:
        scan_data: dict with scan details (target_url, status, started_at, completed_at, etc.)
        vulnerabilities: list of vulnerability dicts
        risk_score: dict with risk_score, severity_level, grade, contributing_factors, ai_explanation
        threat_data: list of threat feed dicts or dict with domain reputation
        output_path: file path to save the PDF
        
    Returns:
        The output_path string.
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=50,
        title='CyberGuard AI - Security Assessment Report',
        author='CyberGuard AI Platform'
    )

    styles = _get_styles()
    elements = []

    # Build each section
    _build_title_page(elements, styles, scan_data, risk_score)
    _build_executive_summary(elements, styles, scan_data, vulnerabilities, risk_score)
    _build_risk_assessment(elements, styles, risk_score)
    _build_vulnerability_table(elements, styles, vulnerabilities)
    _build_detailed_findings(elements, styles, vulnerabilities)
    _build_threat_intelligence(elements, styles, threat_data)
    _build_recommendations(elements, styles, vulnerabilities, risk_score)
    # Technical detail sections
    _build_port_scan_section(elements, styles, scan_data)
    _build_ssl_section(elements, styles, scan_data)
    _build_headers_section(elements, styles, scan_data)
    _build_directory_section(elements, styles, scan_data)
    _build_appendix(elements, styles, scan_data)

    # Build the PDF
    doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)

    return output_path

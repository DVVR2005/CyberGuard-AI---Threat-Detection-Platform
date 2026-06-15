"""
Scanner routes for CyberGuard AI.
Handles scan initiation, retrieval, and deletion with tenant isolation and RBAC.
"""

import json
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, current_app

import models
from routes.auth import token_required, role_required
from services import scanner_service, owasp_engine, risk_scorer, threat_intel_service
from services.mitre_mapping import get_mitre_mapping

scanner_bp = Blueprint('scanner', __name__, url_prefix='/api/scans')


def _parse_json_field(value):
    """Safely parse a JSON string field; return the original if already parsed or on error."""
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def trigger_websocket_alert(event, data, tenant_id=None):
    """Utility to emit Socket.io alerts to users."""
    try:
        socketio = current_app.extensions.get('socketio')
        if socketio:
            # Broadcast to all clients (in production, we'd scope to a tenant room)
            socketio.emit(event, data)
    except Exception as e:
        current_app.logger.warning(f"Failed to emit socketio event: {e}")


@scanner_bp.route('', methods=['POST'])
@token_required
@role_required(['admin', 'analyst'])
def create_scan(current_user):
    """Initiate a new security scan."""
    try:
        tenant_id = current_user['tenant_id']
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400

        url = data.get('url', '').strip()

        # Validate URL
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        if not url.startswith(('http://', 'https://')):
            return jsonify({'success': False, 'error': 'URL must start with http:// or https://'}), 400

        parsed = urlparse(url)
        if not parsed.netloc:
            return jsonify({'success': False, 'error': 'Invalid URL format'}), 400

        domain = parsed.netloc

        # Emit websocket starting event
        trigger_websocket_alert('scan_started', {
            'target_url': url,
            'message': 'Scanning initiated in background...'
        })

        # Timestamps
        started_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # 1. Run full scan
        scan_results = scanner_service.run_full_scan(url)

        # 2. Classify vulnerabilities
        vulnerabilities = owasp_engine.classify_vulnerabilities(scan_results)

        # 3. Calculate risk score
        risk_score_data = risk_scorer.calculate_risk_score(scan_results, vulnerabilities)

        # 4. Get domain reputation
        reputation = threat_intel_service.get_domain_reputation(domain)

        completed_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # 5. Save scan to database
        scan_id = models.create_scan(
            tenant_id=tenant_id,
            user_id=current_user['id'],
            target_url=url,
            port_results=json.dumps(scan_results['port_results']),
            ssl_results=json.dumps(scan_results['ssl_results']),
            header_results=json.dumps(scan_results['header_results']),
            directory_results=json.dumps(scan_results['directory_results']),
            started_at=started_at,
            completed_at=completed_at
        )

        # 6. Save vulnerabilities
        saved_vulns = []
        for vuln in vulnerabilities:
            # Enrich vulnerability with MITRE ATT&CK mapping context
            mitre_data = get_mitre_mapping(vuln.get('cwe_id'))
            vuln_title_enriched = vuln['title']
            
            vuln_id = models.create_vulnerability(
                scan_id=scan_id,
                owasp_category=vuln['owasp_category'],
                title=vuln_title_enriched,
                description=vuln['description'],
                severity=vuln['severity'],
                affected_endpoint=vuln['affected_endpoint'],
                remediation=vuln['remediation'],
                cwe_id=vuln['cwe_id'],
                cvss_score=vuln['cvss_score']
            )
            
            # Map for local response
            vuln_copy = dict(vuln)
            vuln_copy['id'] = vuln_id
            vuln_copy['mitre_tactic'] = mitre_data['tactic_name']
            vuln_copy['mitre_technique'] = f"{mitre_data['technique_name']} ({mitre_data['technique_id']})"
            saved_vulns.append(vuln_copy)

            # Generate a SIEM Event if the vulnerability is Critical or High
            if vuln['severity'] in ('Critical', 'High'):
                models.create_siem_event(
                    tenant_id=tenant_id,
                    event_type='vulnerability_detected',
                    severity=vuln['severity'],
                    source_ip=domain,
                    description=f"High risk vuln detected during scan of {url}: {vuln['title']} ({vuln['cwe_id']})"
                )

        # 7. Save risk score
        models.create_risk_score(
            scan_id=scan_id,
            risk_score=risk_score_data['risk_score'],
            severity_level=risk_score_data['severity_level'],
            grade=risk_score_data['grade'],
            contributing_factors=json.dumps(risk_score_data['contributing_factors']),
            ai_explanation=risk_score_data['ai_explanation']
        )

        # 8. Save threat feed
        models.create_threat_feed(
            scan_id=scan_id,
            domain=domain,
            reputation=reputation['status'],
            threat_data=json.dumps(reputation)
        )

        # 9. Audit log
        models.create_audit_log(
            tenant_id=tenant_id,
            user_id=current_user['id'],
            action='scan_initiated',
            details=f'Full scan initiated for {url} (Scan ID: {scan_id})',
            ip_address=request.remote_addr,
            status='success'
        )

        # Build response
        response = {
            'success': True,
            'scan': {
                'id': scan_id,
                'target_url': url,
                'status': 'completed',
                'scan_type': 'full',
                'port_results': scan_results['port_results'],
                'ssl_results': scan_results['ssl_results'],
                'header_results': scan_results['header_results'],
                'directory_results': scan_results['directory_results'],
                'vulnerabilities': saved_vulns,
                'risk_score': risk_score_data,
                'threat_intel': reputation,
                'started_at': started_at,
                'completed_at': completed_at
            }
        }

        # Emit websocket finish alert
        trigger_websocket_alert('scan_completed', {
            'scan_id': scan_id,
            'target_url': url,
            'risk_score': risk_score_data['risk_score'],
            'grade': risk_score_data['grade'],
            'message': f"Scan complete for {url} (Grade: {risk_score_data['grade']})"
        })

        return jsonify(response), 201

    except Exception as e:
        # Log failure
        trigger_websocket_alert('scan_failed', {
            'target_url': url,
            'message': f"Scan failed: {str(e)}"
        })
        return jsonify({'success': False, 'error': f'Scan failed: {str(e)}'}), 500


@scanner_bp.route('', methods=['GET'])
@token_required
def list_scans(current_user):
    """List scans inside user's tenant."""
    try:
        tenant_id = current_user['tenant_id']
        # Admin / Analyst sees all. Standard User sees only their own.
        if current_user['role'] in ('admin', 'analyst'):
            scans = models.get_all_scans(tenant_id)
        else:
            scans = models.get_scans_by_user(current_user['id'], tenant_id)

        result = []
        for scan in scans:
            vulns = models.get_vulnerabilities_by_scan(scan['id'])
            vuln_count = len(vulns)

            rs = models.get_risk_score_by_scan(scan['id'])
            risk_score_val = rs['risk_score'] if rs else None
            grade = rs['grade'] if rs else None

            result.append({
                'id': scan['id'],
                'target_url': scan['target_url'],
                'status': scan['status'],
                'scan_type': scan.get('scan_type', 'full'),
                'vulnerability_count': vuln_count,
                'risk_score': risk_score_val,
                'grade': grade,
                'created_at': scan['created_at']
            })

        return jsonify({'success': True, 'scans': result}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/<int:scan_id>', methods=['GET'])
@token_required
def get_scan(current_user, scan_id):
    """Get detailed scan data by ID, verifying tenant alignment."""
    try:
        tenant_id = current_user['tenant_id']
        scan = models.get_scan_by_id(scan_id, tenant_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found in your workspace'}), 404

        # Enforce view policy for standard user role
        if current_user['role'] not in ('admin', 'analyst') and scan['user_id'] != current_user['id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Get related data
        vulnerabilities = models.get_vulnerabilities_by_scan(scan_id)
        risk_score = models.get_risk_score_by_scan(scan_id)
        threat_feeds = models.get_threat_feeds_by_scan(scan_id)

        # Enrich vulnerabilities with MITRE ATT&CK Mapping
        enriched_vulns = []
        for v in vulnerabilities:
            vuln_dict = dict(v)
            mitre_data = get_mitre_mapping(v.get('cwe_id'))
            vuln_dict['mitre_tactic'] = mitre_data['tactic_name']
            vuln_dict['mitre_technique'] = f"{mitre_data['technique_name']} ({mitre_data['technique_id']})"
            enriched_vulns.append(vuln_dict)

        # Parse JSON fields
        scan_response = {
            'id': scan['id'],
            'user_id': scan['user_id'],
            'target_url': scan['target_url'],
            'status': scan['status'],
            'scan_type': scan.get('scan_type', 'full'),
            'port_results': _parse_json_field(scan.get('port_results')),
            'ssl_results': _parse_json_field(scan.get('ssl_results')),
            'header_results': _parse_json_field(scan.get('header_results')),
            'directory_results': _parse_json_field(scan.get('directory_results')),
            'started_at': scan.get('started_at'),
            'completed_at': scan.get('completed_at'),
            'created_at': scan['created_at']
        }

        # Parse risk score contributing_factors
        risk_response = None
        if risk_score:
            risk_response = dict(risk_score)
            risk_response['contributing_factors'] = _parse_json_field(
                risk_score.get('contributing_factors')
            )

        # Parse threat feed data
        threat_response = []
        for tf in threat_feeds:
            entry = dict(tf)
            entry['threat_data'] = _parse_json_field(tf.get('threat_data'))
            threat_response.append(entry)

        return jsonify({
            'success': True,
            'scan': scan_response,
            'vulnerabilities': enriched_vulns,
            'risk_score': risk_response,
            'threat_intel': threat_response
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/<int:scan_id>', methods=['DELETE'])
@token_required
@role_required(['admin', 'analyst'])
def delete_scan(current_user, scan_id):
    """Delete a scan by ID, verifying tenant alignment."""
    try:
        tenant_id = current_user['tenant_id']
        scan = models.get_scan_by_id(scan_id, tenant_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found in your workspace'}), 404

        models.delete_scan(scan_id, tenant_id)

        models.create_audit_log(
            tenant_id=tenant_id,
            user_id=current_user['id'],
            action='scan_deleted',
            details=f'Scan {scan_id} for {scan["target_url"]} deleted',
            ip_address=request.remote_addr,
            status='success'
        )

        return jsonify({'success': True, 'message': 'Scan deleted'}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

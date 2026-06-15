"""
Report routes for CyberGuard AI.
Handles PDF report generation, listing, and download with tenant scoping and RBAC restrictions.
"""

import os
import json
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file

from config import Config
import models
from routes.auth import token_required, role_required
from services import report_generator

reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


def _parse_json_field(value):
    """Safely parse a JSON string field."""
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


@reports_bp.route('/generate/<int:scan_id>', methods=['POST'])
@token_required
@role_required(['admin', 'analyst'])
def generate_report(current_user, scan_id):
    """Generate a PDF security assessment report for a scan. Restricted to Admin/Analyst."""
    try:
        tenant_id = current_user['tenant_id']
        
        # Get scan within tenant
        scan = models.get_scan_by_id(scan_id, tenant_id)
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found in your workspace'}), 404

        # Get related data
        vulnerabilities = models.get_vulnerabilities_by_scan(scan_id)
        risk_score = models.get_risk_score_by_scan(scan_id)
        threat_feeds = models.get_threat_feeds_by_scan(scan_id)

        # Parse JSON fields in scan data
        scan_data = dict(scan)
        scan_data['port_results'] = _parse_json_field(scan.get('port_results'))
        scan_data['ssl_results'] = _parse_json_field(scan.get('ssl_results'))
        scan_data['header_results'] = _parse_json_field(scan.get('header_results'))
        scan_data['directory_results'] = _parse_json_field(scan.get('directory_results'))

        # Parse risk score
        risk_data = None
        if risk_score:
            risk_data = dict(risk_score)
            risk_data['contributing_factors'] = _parse_json_field(
                risk_score.get('contributing_factors')
            )

        # Parse threat feed data
        threat_data = []
        for tf in threat_feeds:
            entry = dict(tf)
            entry['threat_data'] = _parse_json_field(tf.get('threat_data'))
            threat_data.append(entry)

        # Generate filename and path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'CyberGuard_Report_{scan_id}_{timestamp}.pdf'
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(Config.REPORTS_DIR, filename)

        # Generate PDF
        report_generator.generate_report(
            scan_data=scan_data,
            vulnerabilities=vulnerabilities,
            risk_score=risk_data,
            threat_data=threat_data,
            output_path=output_path
        )

        # Save report record with tenant_id
        report_id = models.create_report(tenant_id, scan_id, current_user['id'], filename, output_path)

        # Audit log
        models.create_audit_log(
            tenant_id, current_user['id'], 'report_generated',
            f'Report generated for scan {scan_id}: {filename}',
            request.remote_addr, 'success'
        )

        return jsonify({
            'success': True,
            'report': {
                'id': report_id,
                'scan_id': scan_id,
                'filename': filename,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': f'Report generation failed: {str(e)}'}), 500


@reports_bp.route('', methods=['GET'])
@token_required
def list_reports(current_user):
    """List reports for current user/tenant depending on permissions."""
    try:
        tenant_id = current_user['tenant_id']
        if current_user['role'] in ('admin', 'analyst'):
            reports = models.get_all_reports(tenant_id)
        else:
            # Users see only reports they triggered
            reports = models.get_reports_by_user(current_user['id'], tenant_id)

        return jsonify({'success': True, 'reports': reports}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@reports_bp.route('/<int:report_id>/download', methods=['GET'])
@token_required
def download_report(current_user, report_id):
    """Download a PDF report file, verifying tenant bounds."""
    try:
        tenant_id = current_user['tenant_id']
        report = models.get_report_by_id(report_id, tenant_id)
        if not report:
            return jsonify({'success': False, 'error': 'Report not found in your workspace'}), 404

        # Enforce view isolation for standard user role
        if current_user['role'] not in ('admin', 'analyst') and report['user_id'] != current_user['id']:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Check file exists
        if not os.path.exists(report['filepath']):
            return jsonify({'success': False, 'error': 'Report file not found on disk'}), 404

        return send_file(
            report['filepath'],
            mimetype='application/pdf',
            as_attachment=True,
            download_name=report['filename']
        )

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

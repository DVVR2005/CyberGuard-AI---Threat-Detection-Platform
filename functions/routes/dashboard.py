"""
Dashboard routes for CyberGuard AI.
Provides statistics, chart data, and research metrics scoped by tenant and user role.
"""

from flask import Blueprint, jsonify
import models
from database import get_db
from routes.auth import token_required

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


@dashboard_bp.route('/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Get dashboard statistics scoped to user tenant and role."""
    try:
        tenant_id = current_user['tenant_id']
        # Admin and Analyst see tenant-wide stats. User sees only their own.
        user_id = current_user['id'] if current_user['role'] == 'user' else None
        stats = models.get_dashboard_stats(tenant_id, user_id)

        return jsonify({'success': True, 'stats': stats}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_bp.route('/charts', methods=['GET'])
@token_required
def get_charts(current_user):
    """Get aggregated chart data for the dashboard."""
    try:
        tenant_id = current_user['tenant_id']
        user_id = current_user['id'] if current_user['role'] == 'user' else None
        charts = models.get_dashboard_charts(tenant_id, user_id)

        return jsonify({'success': True, 'charts': charts}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_bp.route('/recent', methods=['GET'])
@token_required
def get_recent(current_user):
    """Get the most recent scans with risk scores and vulnerability counts."""
    try:
        tenant_id = current_user['tenant_id']
        user_id = current_user['id'] if current_user['role'] == 'user' else None
        recent = models.get_recent_scans(tenant_id, user_id, limit=10)

        return jsonify({'success': True, 'recent': recent}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_bp.route('/research-metrics', methods=['GET'])
@token_required
def get_research_metrics(current_user):
    """Get statistics and correlation datasets for research metrics dashboard."""
    try:
        # Query CVE data for EPSS vs CVSS plotting
        db = get_db()
        try:
            cves = db.execute(
                "SELECT cve_id, title, cvss_score, epss_score, epss_percentile, severity FROM cves LIMIT 150"
            ).fetchall()
            cve_list = [dict(c) for c in cves]
        finally:
            db.close()

        # Mean Time To Remediation (MTTR) by vulnerability severity level (in days)
        remediation_timeline = {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'data': [2.4, 6.1, 14.8, 29.5] # average days
        }

        # Global threat intelligence trends
        threat_distribution = {
            'labels': ['Ransomware', 'Phishing', 'DDoS', 'Supply Chain', 'Credential Stuffing'],
            'data': [34, 48, 19, 12, 25] # relative percentage index
        }

        return jsonify({
            'success': True,
            'metrics': {
                'cves': cve_list,
                'remediation_timeline': remediation_timeline,
                'threat_distribution': threat_distribution
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

"""
Threat Intelligence routes for CyberGuard AI.
Provides CVE search with EPSS scores, domain reputation, and global threat status.
"""

from flask import Blueprint, jsonify, request
from routes.auth import token_required
from services.threat_intel_service import get_domain_reputation, get_global_threat_status
from services.elasticsearch_service import es_service

threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/api/threat-intel')


@threat_intel_bp.route('/cves', methods=['GET'])
@token_required
def cves(current_user):
    """
    Search CVE database with CVSS, EPSS score filters, and search query.
    Utilizes Elasticsearch with automatic database fallback.
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        severity = request.args.get('severity', None)
        query = request.args.get('q', '').strip()
        min_cvss = request.args.get('min_cvss', 0.0, type=float)
        min_epss = request.args.get('min_epss', 0.0, type=float)
        sort_by = request.args.get('sort_by', 'cvss_score')

        # Query using elasticsearch service (which falls back to models.search_cves)
        cves_list = es_service.search_cves(
            query_str=query,
            min_cvss=min_cvss,
            min_epss=min_epss,
            severity=severity,
            sort_by=sort_by,
            limit=limit
        )

        return jsonify({'success': True, 'cves': cves_list}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/domain/<path:domain>', methods=['GET'])
@token_required
def domain_reputation(current_user, domain):
    """Check domain reputation."""
    try:
        if not domain or len(domain) < 3:
            return jsonify({'success': False, 'error': 'Invalid domain'}), 400

        reputation = get_domain_reputation(domain)
        return jsonify({'success': True, 'reputation': reputation}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@threat_intel_bp.route('/global-status', methods=['GET'])
@token_required
def global_status(current_user):
    """Get global threat level overview."""
    try:
        status = get_global_threat_status()
        return jsonify({'success': True, 'global': status}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

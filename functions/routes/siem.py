"""
SIEM Event Monitoring routes for CyberGuard AI.
Allows operators to search and audit security events within their tenant.
"""

from flask import Blueprint, jsonify, request
from routes.auth import token_required, role_required
from services.elasticsearch_service import es_service

siem_bp = Blueprint('siem', __name__, url_prefix='/api/siem')


@siem_bp.route('', methods=['GET'])
@token_required
@role_required(['admin', 'analyst'])
def get_events(current_user):
    """
    Search and retrieve SIEM logs for the current tenant.
    Utilizes Elasticsearch with automatic database fallback.
    """
    try:
        tenant_id = current_user['tenant_id']
        query = request.args.get('q', '').strip()
        severity = request.args.get('severity', None)
        limit = request.args.get('limit', 50, type=int)

        # Call es_service (which falls back to SQL query)
        events = es_service.search_siem_events(
            tenant_id=tenant_id,
            query_str=query,
            severity=severity,
            limit=limit
        )

        return jsonify({'success': True, 'events': events}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

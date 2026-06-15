"""
Admin routes for CyberGuard AI.
All endpoints require admin authentication and are partitioned by tenant.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify
import models
from database import get_db
from routes.auth import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users(current_user):
    """Get all users inside the admin's tenant with their scan counts."""
    try:
        tenant_id = current_user['tenant_id']
        users = models.get_all_users(tenant_id)
        result = []
        for user in users:
            scan_count = models.count_scans_by_user(user['id'], tenant_id)
            result.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'status': user['status'],
                'created_at': user['created_at'],
                'scan_count': scan_count
            })

        return jsonify({'success': True, 'users': result}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(current_user):
    """Update a user's status or role within the admin's tenant."""
    try:
        # Resolve target user id from URL parameter
        # In current flask routes it matches /users/<int:user_id>
        # Let's extract user_id from path
        user_id = int(request.view_args['user_id'])
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400

        # Check target user exists in admin's tenant
        target_user = models.get_user_by_id(user_id)
        if not target_user or target_user['tenant_id'] != current_user['tenant_id']:
            return jsonify({'success': False, 'error': 'User not found in your tenant'}), 404

        fields = {}

        # Handle status update
        if 'status' in data:
            status = data['status']
            if status not in ('active', 'suspended'):
                return jsonify({'success': False, 'error': 'Status must be active or suspended'}), 400
            fields['status'] = status

        # Handle role update
        if 'role' in data:
            if current_user['id'] == user_id:
                return jsonify({'success': False, 'error': 'Cannot modify your own role'}), 400
            role = data['role']
            if role not in ('admin', 'analyst', 'user'):
                return jsonify({'success': False, 'error': 'Role must be admin, analyst, or user'}), 400
            fields['role'] = role

        if not fields:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400

        models.update_user(user_id, **fields)

        # Audit log
        models.create_audit_log(
            current_user['tenant_id'], current_user['id'], 'user_updated',
            f'User {user_id} ({target_user["email"]}) updated: {fields}',
            request.remote_addr, 'success'
        )

        updated_user = models.get_user_by_id(user_id)
        return jsonify({
            'success': True,
            'user': {
                'id': updated_user['id'],
                'name': updated_user['name'],
                'email': updated_user['email'],
                'role': updated_user['role'],
                'status': updated_user['status']
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    """Delete a user account within the admin's tenant."""
    try:
        if current_user['id'] == user_id:
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

        target_user = models.get_user_by_id(user_id)
        if not target_user or target_user['tenant_id'] != current_user['tenant_id']:
            return jsonify({'success': False, 'error': 'User not found in your tenant'}), 404

        models.delete_user(user_id)

        models.create_audit_log(
            current_user['tenant_id'], current_user['id'], 'user_deleted',
            f'User {user_id} ({target_user["email"]}) deleted',
            request.remote_addr, 'success'
        )

        return jsonify({'success': True, 'message': 'User deleted'}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/scans', methods=['GET'])
@admin_required
def list_all_scans(current_user):
    """Get all scans in the admin's tenant with user details and vulnerability summaries."""
    try:
        tenant_id = current_user['tenant_id']
        scans = models.get_all_scans(tenant_id)
        result = []

        for scan in scans:
            user = models.get_user_by_id(scan['user_id'])
            user_name = user['name'] if user else 'Unknown'
            user_email = user['email'] if user else 'Unknown'

            rs = models.get_risk_score_by_scan(scan['id'])
            risk_score_val = rs['risk_score'] if rs else None

            vulns = models.get_vulnerabilities_by_scan(scan['id'])
            vuln_count = len(vulns)

            result.append({
                'id': scan['id'],
                'user_id': scan['user_id'],
                'user_name': user_name,
                'user_email': user_email,
                'target_url': scan['target_url'],
                'status': scan['status'],
                'risk_score': risk_score_val,
                'vulnerability_count': vuln_count,
                'created_at': scan['created_at']
            })

        return jsonify({'success': True, 'scans': result}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs(current_user):
    """Get audit logs for the admin's tenant."""
    try:
        limit = request.args.get('limit', 100, type=int)
        action_filter = request.args.get('action', None)
        tenant_id = current_user['tenant_id']

        logs = models.get_all_audit_logs(limit=limit, tenant_id=tenant_id)

        if action_filter:
            logs = [log for log in logs if log.get('action') == action_filter]

        return jsonify({'success': True, 'logs': logs}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_admin_stats(current_user):
    """Get tenant-wide stats for administration dashboard."""
    try:
        tenant_id = current_user['tenant_id']
        db = get_db()
        try:
            total_users = db.execute("SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ?", (tenant_id,)).fetchone()['cnt']
            active_users = db.execute(
                "SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ? AND status = 'active'", (tenant_id,)
            ).fetchone()['cnt']
            suspended_users = db.execute(
                "SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ? AND status = 'suspended'", (tenant_id,)
            ).fetchone()['cnt']
            
            total_scans = db.execute("SELECT COUNT(*) as cnt FROM scans WHERE tenant_id = ?", (tenant_id,)).fetchone()['cnt']
            
            total_vulns = db.execute(
                "SELECT COUNT(*) as cnt FROM vulnerabilities v JOIN scans s ON v.scan_id = s.id WHERE s.tenant_id = ?", (tenant_id,)
            ).fetchone()['cnt']
            
            total_reports = db.execute("SELECT COUNT(*) as cnt FROM reports WHERE tenant_id = ?", (tenant_id,)).fetchone()['cnt']

            avg_row = db.execute(
                "SELECT AVG(rs.risk_score) as avg_score FROM risk_scores rs JOIN scans s ON rs.scan_id = s.id WHERE s.tenant_id = ?", (tenant_id,)
            ).fetchone()
            avg_risk = round(avg_row['avg_score'], 1) if avg_row['avg_score'] else 0.0

            critical_findings = db.execute(
                """SELECT COUNT(*) as cnt FROM vulnerabilities v 
                   JOIN scans s ON v.scan_id = s.id 
                   WHERE s.tenant_id = ? AND v.severity = 'Critical'""", (tenant_id,)
            ).fetchone()['cnt']

            scans_today = db.execute(
                "SELECT COUNT(*) as cnt FROM scans WHERE tenant_id = ? AND date(created_at) = date('now')", (tenant_id,)
            ).fetchone()['cnt']

            new_users_month = db.execute(
                "SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ? AND created_at >= datetime('now', 'start of month')", (tenant_id,)
            ).fetchone()['cnt']
        finally:
            db.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'active_users': active_users,
                'suspended_users': suspended_users,
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulns,
                'total_reports': total_reports,
                'avg_risk_score': avg_risk,
                'critical_findings': critical_findings,
                'scans_today': scans_today,
                'new_users_this_month': new_users_month
            }
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

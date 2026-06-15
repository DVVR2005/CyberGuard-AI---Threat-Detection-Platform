"""
Authentication routes, JWT middleware, and RBAC / rate-limiting decorators for CyberGuard AI.
"""

import re
import functools
from datetime import datetime, timedelta

import bcrypt
import jwt
from flask import Blueprint, request, jsonify

from config import Config
import models
from services.cache_service import cache

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


# =============================================================================
# JWT & RBAC Middleware Decorators
# =============================================================================

def token_required(f):
    """Decorator that validates JWT token and injects user dict into the wrapped function."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Check if user has already been injected by a previous decorator
        if args and isinstance(args[0], dict) and 'id' in args[0] and 'tenant_id' in args[0]:
            return f(args[0], *args[1:], **kwargs)

        token = None

        # Read token from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]

        if not token:
            return jsonify({'success': False, 'error': 'Authentication token is missing'}), 401

        try:
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
            user = models.get_user_by_id(payload.get('user_id'))
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 401
            if user.get('status') == 'suspended':
                return jsonify({'success': False, 'error': 'Account is suspended'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401

        return f(user, *args, **kwargs)

    return decorated


def role_required(allowed_roles):
    """Decorator to enforce RBAC logic for endpoints."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            # Check if user has already been injected by a previous decorator
            if args and isinstance(args[0], dict) and 'id' in args[0] and 'tenant_id' in args[0]:
                user = args[0]
                args = args[1:]
                if user.get('role') not in allowed_roles:
                    return jsonify({'success': False, 'error': 'Access denied: insufficient permissions'}), 403
                return f(user, *args, **kwargs)

            token = None
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]

            if not token:
                return jsonify({'success': False, 'error': 'Authentication token is missing'}), 401

            try:
                payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
                user = models.get_user_by_id(payload.get('user_id'))
                if not user:
                    return jsonify({'success': False, 'error': 'User not found'}), 401
                if user.get('status') == 'suspended':
                    return jsonify({'success': False, 'error': 'Account is suspended'}), 403
                if user.get('role') not in allowed_roles:
                    return jsonify({'success': False, 'error': 'Access denied: insufficient permissions'}), 403
            except jwt.ExpiredSignatureError:
                return jsonify({'success': False, 'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'success': False, 'error': 'Invalid token'}), 401

            return f(user, *args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    """Convenience decorator checking for Admin role."""
    return role_required(['admin'])(f)


# =============================================================================
# API Rate Limiter Decorator
# =============================================================================

def rate_limit(limit_key_prefix, max_requests=10, period=60):
    """Simple rate limiter using Redis / memory fallback."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr or 'unknown'
            key = f"rate:{limit_key_prefix}:{ip}"
            
            current_count = cache.get(key)
            if current_count is None:
                cache.set(key, 1, ex=period)
            else:
                count = int(current_count)
                if count >= max_requests:
                    return jsonify({
                        'success': False,
                        'error': f'Rate limit exceeded. Maximum {max_requests} requests per {period} seconds.'
                    }), 429
                cache.set(key, count + 1, ex=period)
                
            return f(*args, **kwargs)
        return decorated
    return decorator


# =============================================================================
# Helper Functions
# =============================================================================

def _generate_token(user):
    """Generate a JWT token for the given user."""
    tenant = models.get_tenant_by_id(user['tenant_id'])
    tenant_name = tenant['name'] if tenant else 'Default Org'
    payload = {
        'user_id': user['id'],
        'email': user['email'],
        'role': user['role'],
        'tenant_id': user['tenant_id'],
        'tenant_name': tenant_name,
        'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')


def _sanitize_user(user):
    """Return a safe user dict without the password hash."""
    tenant = models.get_tenant_by_id(user['tenant_id'])
    tenant_name = tenant['name'] if tenant else 'Default Org'
    return {
        'id': user['id'],
        'tenant_id': user['tenant_id'],
        'tenant_name': tenant_name,
        'name': user['name'],
        'email': user['email'],
        'role': user['role'],
        'status': user['status'],
        'created_at': user['created_at']
    }


def _validate_email(email):
    """Basic email format validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# =============================================================================
# Endpoints
# =============================================================================

@auth_bp.route('/register', methods=['POST'])
@rate_limit('register', max_requests=10, period=60)
def register():
    """Register a new user account with tenant partitioning."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400

        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        role = data.get('role', 'analyst').strip().lower()
        tenant_name = data.get('tenant_name', '').strip()

        # Validation
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        if not _validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        if not password:
            return jsonify({'success': False, 'error': 'Password is required'}), 400
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        if password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'}), 400

        # Check if email already exists
        existing = models.get_user_by_email(email)
        if existing:
            return jsonify({'success': False, 'error': 'Email already registered'}), 400

        # Enforce valid role names
        if role not in ('user', 'analyst', 'admin'):
            role = 'user'

        # Resolve Tenant ID
        if not tenant_name:
            tenant_name = "Default Org"

        tenant = models.get_tenant_by_name(tenant_name)
        if not tenant:
            tenant_id = models.create_tenant(tenant_name)
        else:
            tenant_id = tenant['id']

        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create user
        user_id = models.create_user(tenant_id, name, email, password_hash, role)
        user = models.get_user_by_id(user_id)

        # Generate token
        token = _generate_token(user)

        # Audit log
        models.create_audit_log(
            tenant_id, user_id, 'user_registered',
            f'New user registered: {email} (role: {role}, tenant: {tenant_name})',
            request.remote_addr, 'success'
        )

        return jsonify({
            'success': True,
            'token': token,
            'user': _sanitize_user(user)
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': f'Registration failed: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
@rate_limit('login', max_requests=10, period=60)
def login():
    """Authenticate user and return JWT token."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # Find user
        user = models.get_user_by_email(email)
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        tenant_id = user['tenant_id']

        # Check if account is locked
        if user.get('locked_until'):
            locked_until = datetime.strptime(user['locked_until'], '%Y-%m-%d %H:%M:%S')
            if datetime.utcnow() < locked_until:
                remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                models.create_audit_log(
                    tenant_id, user['id'], 'login_failed',
                    f'Blocked login attempt on locked account for {email}',
                    request.remote_addr, 'failure'
                )
                return jsonify({
                    'success': False,
                    'error': f'Account locked. Try again after {remaining} minutes'
                }), 423
            else:
                models.reset_failed_attempts(user['id'])

        # Check if account is suspended
        if user.get('status') == 'suspended':
            models.create_audit_log(
                tenant_id, user['id'], 'login_failed',
                f'Blocked login attempt on suspended account for {email}',
                request.remote_addr, 'failure'
            )
            return jsonify({'success': False, 'error': 'Account is suspended. Contact administrator.'}), 403

        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            new_count = models.increment_failed_attempts(user['id'])
            if new_count >= Config.MAX_LOGIN_ATTEMPTS:
                lock_until = (datetime.utcnow() + timedelta(minutes=Config.LOCKOUT_DURATION_MINUTES))
                models.lock_user(user['id'], lock_until.strftime('%Y-%m-%d %H:%M:%S'))
                models.create_audit_log(
                    tenant_id, user['id'], 'account_locked',
                    f'Account locked after {new_count} failed attempts',
                    request.remote_addr, 'success'
                )
                return jsonify({
                    'success': False,
                    'error': f'Account locked due to too many failed attempts. Try again after {Config.LOCKOUT_DURATION_MINUTES} minutes'
                }), 423

            models.create_audit_log(
                tenant_id, user['id'], 'login_failed',
                f'Failed login attempt ({new_count}/{Config.MAX_LOGIN_ATTEMPTS})',
                request.remote_addr, 'failure'
            )
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        # Successful login
        models.reset_failed_attempts(user['id'])
        token = _generate_token(user)

        models.create_audit_log(
            tenant_id, user['id'], 'login_success',
            f'User logged in successfully',
            request.remote_addr, 'success'
        )

        return jsonify({
            'success': True,
            'token': token,
            'user': _sanitize_user(user)
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': f'Login failed: {str(e)}'}), 500


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_me(current_user):
    """Get current authenticated user's profile."""
    try:
        return jsonify({
            'success': True,
            'user': _sanitize_user(current_user)
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@auth_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """Update user profile details (name and optionally password)."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400

        name = data.get('name', '').strip()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400

        # Build update dictionary
        updates = {'name': name}

        # Check if we also want to change the password
        if new_password:
            if not current_password:
                return jsonify({'success': False, 'error': 'Current password is required to change password'}), 400
            
            # Verify current password
            if not bcrypt.checkpw(current_password.encode('utf-8'), current_user['password_hash'].encode('utf-8')):
                return jsonify({'success': False, 'error': 'Incorrect current password'}), 400

            if len(new_password) < 8:
                return jsonify({'success': False, 'error': 'New password must be at least 8 characters'}), 400

            # Hash new password
            new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            updates['password_hash'] = new_hash

        # Update user in DB
        models.update_user(current_user['id'], **updates)

        # Retrieve updated user and sanitize
        updated_user = models.get_user_by_id(current_user['id'])

        # Audit logging
        models.create_audit_log(
            tenant_id=current_user['tenant_id'],
            user_id=current_user['id'],
            action='profile_updated',
            details=f'Profile details updated for user {updated_user["email"]}',
            ip_address=request.remote_addr,
            status='success'
        )

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': _sanitize_user(updated_user)
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

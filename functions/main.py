"""
CyberGuard AI - Cloud Functions Entry Point
Wraps the Flask application for Firebase Cloud Functions (2nd gen).
"""

import os
import sys
import shutil

# Ensure the functions directory is in the path
sys.path.insert(0, os.path.dirname(__file__))

# Cloud Functions write to /tmp — copy the bundled DB there on cold start
_DB_SOURCE = os.path.join(os.path.dirname(__file__), 'cyberguard.db')
_DB_TARGET = '/tmp/cyberguard.db'

if not os.path.exists(_DB_TARGET) and os.path.exists(_DB_SOURCE):
    shutil.copy2(_DB_SOURCE, _DB_TARGET)

# Override the DATABASE_PATH before importing the app
os.environ['DATABASE_PATH'] = _DB_TARGET
os.environ['REPORTS_DIR'] = '/tmp/reports'

# Ensure reports directory exists
os.makedirs('/tmp/reports', exist_ok=True)

from flask import Flask, render_template
from flask_cors import CORS
from config import Config
from database import init_db, seed_db

# Import Firebase Functions Framework
from firebase_functions import https_fn

def create_app():
    app = Flask(__name__, static_folder=None, template_folder=None)
    app.config.from_object(Config)
    # Override paths for Cloud Functions
    app.config['DATABASE_PATH'] = _DB_TARGET
    app.config['REPORTS_DIR'] = '/tmp/reports'
    CORS(app)

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.scanner import scanner_bp
    from routes.dashboard import dashboard_bp
    from routes.reports import reports_bp
    from routes.admin import admin_bp
    from routes.threat_intel import threat_intel_bp
    from routes.siem import siem_bp
    from routes.ai import ai_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(siem_bp)
    app.register_blueprint(ai_bp)

    # Initialize and seed database
    with app.app_context():
        init_db()
        import sqlite3
        try:
            conn = sqlite3.connect(_DB_TARGET)
            count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            if count == 0:
                seed_db()
            conn.close()
        except Exception:
            seed_db()

    return app

flask_app = create_app()

@https_fn.on_request(
    memory=512,
    timeout_sec=120,
    min_instances=0,
    max_instances=10,
)
def api(req: https_fn.Request) -> https_fn.Response:
    """Firebase Cloud Function entry point — proxies to Flask."""
    with flask_app.request_context(req.environ):
        try:
            rv = flask_app.full_dispatch_request()
            return rv
        except Exception as e:
            flask_app.logger.error(f"Unhandled error: {e}")
            return https_fn.Response(
                response='{"error": "Internal server error"}',
                status=500,
                content_type='application/json'
            )

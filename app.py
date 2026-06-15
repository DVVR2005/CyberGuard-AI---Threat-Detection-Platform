"""
CyberGuard AI - Threat Detection Platform
Main Flask Application Entry Point
"""

from flask import Flask, render_template
from flask_cors import CORS
from config import Config
from database import init_db, seed_db

# Try to import SocketIO
try:
    from flask_socketio import SocketIO
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False

# Try to import Celery
try:
    from celery import Celery
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False


def make_celery(app):
    """Integrates Celery with Flask application context."""
    if not HAS_CELERY:
        return None
    celery = Celery(
        app.import_name,
        backend='redis://localhost:6379/0',
        broker='redis://localhost:6379/0'
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(Config)
    CORS(app)

    # Initialize Socket.io extension
    if HAS_SOCKETIO:
        socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
        app.extensions['socketio'] = socketio

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

    # Serve the SPA shell
    @app.route('/')
    def index():
        return render_template('index.html')

    # Serve Swagger UI Documentation
    @app.route('/api/docs')
    def swagger_docs():
        return render_template('swagger_ui.html')

    # Initialize database
    with app.app_context():
        init_db()

    return app


# Celery app reference for worker execution
flask_app = create_app()
celery_app = make_celery(flask_app)


def main():
    # Seed database if empty
    import sqlite3
    conn = sqlite3.connect(Config.DATABASE_PATH)
    try:
        count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if count == 0:
            seed_db()
            print("[*] Database seeded with demo data.")
        else:
            print(f"[*] Database already has {count} users. Skipping seed.")
    except Exception:
        seed_db()
        print("[*] Database seeded with demo data.")
    finally:
        conn.close()

    print("\n" + "=" * 60)
    print("  CyberGuard AI - Enterprise Threat Detection Platform")
    print("  Running at: http://localhost:5000")
    print("  API Documentation at: http://localhost:5000/api/docs")
    print("=" * 60)
    print("  Demo Credentials:")
    print("    Admin:   admin@cyberguard.ai / Admin@123")
    print("    Analyst: analyst@cyberguard.ai / Analyst@123")
    print("    User:    user@cyberguard.ai / User@123")
    print("=" * 60 + "\n")

    # Run with Socket.io wrapper if installed
    if HAS_SOCKETIO:
        socketio = flask_app.extensions.get('socketio')
        socketio.run(flask_app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    else:
        flask_app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()

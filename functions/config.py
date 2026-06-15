import os
import secrets


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
    JWT_EXPIRY_HOURS = 24
    DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'cyberguard.db'))
    REPORTS_DIR = os.environ.get('REPORTS_DIR', os.path.join(os.path.dirname(__file__), 'reports'))
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    RATE_LIMIT_PER_MINUTE = 30

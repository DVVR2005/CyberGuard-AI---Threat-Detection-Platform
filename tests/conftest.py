import os
import tempfile
import pytest
from app import create_app
from config import Config
from database import init_db, seed_db


@pytest.fixture
def app():
    """Create and configure a clean Flask app instance for each test."""
    db_fd, db_path = tempfile.mkstemp()
    
    # Backup original settings
    old_db_path = Config.DATABASE_PATH
    
    # Override with testing configurations
    Config.DATABASE_PATH = db_path
    Config.TESTING = True
    
    app = create_app()
    
    with app.app_context():
        init_db()
        seed_db()
        
    yield app
    
    # Cleanup database
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass
        
    # Restore original settings
    Config.DATABASE_PATH = old_db_path
    Config.TESTING = False


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

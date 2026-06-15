"""
Caching service for CyberGuard AI.
Uses Redis for caching with a transparent in-memory dictionary fallback.
"""

import json
import logging

logger = logging.getLogger(__name__)

# Try to import Redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis-py not installed. Caching service will use in-memory fallback.")

class CacheService:
    def __init__(self):
        self.redis_client = None
        self.local_cache = {}
        
        if REDIS_AVAILABLE:
            try:
                # Connect to Redis using default localhost:6379 config
                self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True, socket_connect_timeout=2)
                # Test connection
                self.redis_client.ping()
                logger.info("Connected to Redis successfully.")
            except Exception as e:
                self.redis_client = None
                logger.warning(f"Failed to connect to Redis: {e}. Falling back to in-memory cache.")

    def get(self, key):
        """Retrieve key from cache. Returns deserialized JSON or string, or None."""
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    try:
                        return json.loads(val)
                    except json.JSONDecodeError:
                        return val
                return None
            except Exception as e:
                logger.warning(f"Redis get error: {e}")
                # Fallback to local
        
        # In-memory fallback
        return self.local_cache.get(key)

    def set(self, key, value, ex=3600):
        """Set key in cache with a TTL (default 1 hour)."""
        serialized_val = json.dumps(value) if not isinstance(value, str) else value
        
        if self.redis_client:
            try:
                self.redis_client.set(key, serialized_val, ex=ex)
                return True
            except Exception as e:
                logger.warning(f"Redis set error: {e}")
                # Fallback to local
                
        # In-memory fallback
        self.local_cache[key] = value
        # Simple local TTL mechanism isn't strictly necessary for a demo fallback,
        # but storing the raw value is sufficient.
        return True

    def delete(self, key):
        """Delete key from cache."""
        if self.redis_client:
            try:
                self.redis_client.delete(key)
                return True
            except Exception as e:
                logger.warning(f"Redis delete error: {e}")
                
        if key in self.local_cache:
            del self.local_cache[key]
        return True

    def clear(self):
        """Clear the cache."""
        if self.redis_client:
            try:
                self.redis_client.flushdb()
                return True
            except Exception as e:
                logger.warning(f"Redis flushdb error: {e}")
        self.local_cache.clear()
        return True


# Global singleton instance
cache = CacheService()

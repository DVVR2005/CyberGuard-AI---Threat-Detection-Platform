"""
Elasticsearch indexing and search service for CyberGuard AI.
Integrates search operations and provides direct SQLite search fallback.
"""

import logging
import models

logger = logging.getLogger(__name__)

# Try to import Elasticsearch
try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("elasticsearch module not installed. Search service will use database fallback.")

class ElasticsearchService:
    def __init__(self):
        self.es_client = None
        
        if ES_AVAILABLE:
            try:
                # Connect to Elasticsearch local instance
                self.es_client = Elasticsearch("http://localhost:9200", max_retries=1, request_timeout=2)
                # Test connection
                if self.es_client.ping():
                    logger.info("Connected to Elasticsearch successfully.")
                    self._create_indices_if_not_exist()
                else:
                    self.es_client = None
                    logger.warning("Elasticsearch ping failed. Using database fallback.")
            except Exception as e:
                self.es_client = None
                logger.warning(f"Failed to connect to Elasticsearch: {e}. Using database fallback.")

    def _create_indices_if_not_exist(self):
        """Pre-configure indices for events and CVEs if they don't exist."""
        try:
            if not self.es_client.indices.exists(index="siem_events"):
                self.es_client.indices.create(index="siem_events")
            if not self.es_client.indices.exists(index="cves"):
                self.es_client.indices.create(index="cves")
        except Exception as e:
            logger.warning(f"Could not create ES indices: {e}")

    def index_siem_event(self, event):
        """Index a SIEM event into Elasticsearch."""
        if not self.es_client:
            return False
        try:
            doc_id = event.get('id')
            self.es_client.index(index="siem_events", id=str(doc_id), document=event)
            return True
        except Exception as e:
            logger.warning(f"Elasticsearch indexing error (event {event.get('id')}): {e}")
            return False

    def search_siem_events(self, tenant_id=None, query_str="", severity=None, limit=100):
        """
        Search SIEM events. If ES is unavailable, fall back to SQLite.
        """
        if not self.es_client:
            # Fall back to SQLite model call
            return models.get_siem_events(tenant_id=tenant_id, limit=limit, severity=severity, search_query=query_str)
            
        try:
            must_clauses = []
            
            # Scope to tenant
            if tenant_id is not None:
                must_clauses.append({"term": {"tenant_id": tenant_id}})
                
            # Filter by severity
            if severity:
                must_clauses.append({"term": {"severity.keyword": severity}})
                
            # Free-text search matching multiple fields
            if query_str:
                must_clauses.append({
                    "multi_match": {
                        "query": query_str,
                        "fields": ["event_type", "description", "source_ip"]
                    }
                })
                
            query = {
                "bool": {
                    "must": must_clauses
                }
            } if must_clauses else {"match_all": {}}
            
            res = self.es_client.search(
                index="siem_events",
                query=query,
                size=limit,
                sort=[{"created_at": {"order": "desc"}}]
            )
            
            hits = res['hits']['hits']
            return [hit['_source'] for hit in hits]
            
        except Exception as e:
            logger.warning(f"Elasticsearch search failed: {e}. Falling back to database search.")
            return models.get_siem_events(tenant_id=tenant_id, limit=limit, severity=severity, search_query=query_str)

    def index_cve(self, cve):
        """Index a CVE entry into Elasticsearch."""
        if not self.es_client:
            return False
        try:
            cve_id = cve.get('cve_id')
            self.es_client.index(index="cves", id=cve_id, document=cve)
            return True
        except Exception as e:
            logger.warning(f"Elasticsearch indexing error (CVE {cve.get('cve_id')}): {e}")
            return False

    def search_cves(self, query_str="", min_cvss=0.0, min_epss=0.0, severity=None, sort_by='cvss_score', limit=50):
        """
        Search CVEs. If ES is unavailable, fall back to SQLite.
        """
        if not self.es_client:
            # Fall back to SQLite model call
            return models.search_cves(query=query_str, min_cvss=min_cvss, min_epss=min_epss, severity=severity, sort_by=sort_by, limit=limit)
            
        try:
            must_clauses = [
                {"range": {"cvss_score": {"gte": min_cvss}}},
                {"range": {"epss_score": {"gte": min_epss}}}
            ]
            
            if severity:
                must_clauses.append({"term": {"severity.keyword": severity}})
                
            if query_str:
                must_clauses.append({
                    "multi_match": {
                        "query": query_str,
                        "fields": ["cve_id", "title", "description", "affected_products"]
                    }
                })
                
            query = {
                "bool": {
                    "must": must_clauses
                }
            }
            
            # Handle sorting field maps
            sort_field = sort_by
            if sort_by == 'cvss_score':
                sort_field = "cvss_score"
            elif sort_by == 'epss_score':
                sort_field = "epss_score"
            elif sort_by == 'published_date':
                sort_field = "published_date"
            elif sort_by == 'cve_id':
                sort_field = "cve_id.keyword"
                
            res = self.es_client.search(
                index="cves",
                query=query,
                size=limit,
                sort=[{sort_field: {"order": "desc"}}]
            )
            
            hits = res['hits']['hits']
            return [hit['_source'] for hit in hits]
            
        except Exception as e:
            logger.warning(f"Elasticsearch CVE search failed: {e}. Falling back to database search.")
            return models.search_cves(query=query_str, min_cvss=min_cvss, min_epss=min_epss, severity=severity, sort_by=sort_by, limit=limit)


# Global singleton instance
es_service = ElasticsearchService()

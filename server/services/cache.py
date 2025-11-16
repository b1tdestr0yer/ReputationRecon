import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
import hashlib
import config


class AssessmentCache:
    """Lightweight SQLite cache for assessments with timestamps"""
    
    def __init__(self, db_path: str = "assessments_cache.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                cache_key TEXT PRIMARY KEY,
                entity_name TEXT NOT NULL,
                vendor_name TEXT NOT NULL,
                assessment_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_entity_vendor 
            ON assessments(entity_name, vendor_name)
        """)
        
        conn.commit()
        conn.close()
    
    def _generate_key(self, product_name: Optional[str], vendor_name: Optional[str], 
                     url: Optional[str], hash: Optional[str]) -> str:
        """Generate a deterministic cache key"""
        key_parts = []
        if product_name:
            key_parts.append(f"product:{product_name.lower().strip()}")
        if vendor_name:
            key_parts.append(f"vendor:{vendor_name.lower().strip()}")
        if url:
            key_parts.append(f"url:{url.lower().strip()}")
        if hash:
            key_parts.append(f"hash:{hash.lower().strip()}")
        
        key_string = "|".join(sorted(key_parts))
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get(self, product_name: Optional[str] = None, vendor_name: Optional[str] = None,
            url: Optional[str] = None, hash: Optional[str] = None, 
            ttl_days: Optional[int] = None) -> Optional[Tuple[Dict[str, Any], bool]]:
        """
        Retrieve cached assessment with expiration check
        
        Returns:
            Tuple of (cached_data, is_valid) or None if not found
            is_valid indicates if cache is still within TTL
        """
        cache_key = self._generate_key(product_name, vendor_name, url, hash)
        
        # Use config default or provided TTL (7 days for security assessments)
        ttl = ttl_days if ttl_days is not None else config.Config.CACHE_TTL_DAYS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT assessment_data, created_at, updated_at 
            FROM assessments 
            WHERE cache_key = ?
        """, (cache_key,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            data = json.loads(result[0])
            updated_at_str = result[2]
            
            # Parse timestamp
            try:
                if isinstance(updated_at_str, str):
                    # Handle ISO format
                    if 'T' in updated_at_str:
                        updated_at = datetime.fromisoformat(updated_at_str.replace('Z', '+00:00'))
                    else:
                        # SQLite datetime format
                        updated_at = datetime.strptime(updated_at_str, '%Y-%m-%d %H:%M:%S')
                else:
                    updated_at = datetime.fromisoformat(updated_at_str)
            except (ValueError, AttributeError):
                # Fallback: assume it's valid if we can't parse
                updated_at = datetime.now()
            
            # Check if cache is still valid
            expiration_time = updated_at + timedelta(days=ttl)
            is_valid = datetime.now() < expiration_time
            
            # Add cache metadata
            data['cache_key'] = cache_key
            data['cached_at'] = result[1]
            data['updated_at'] = result[2]
            data['is_cached'] = True
            data['cache_valid'] = is_valid
            data['cache_expires_at'] = expiration_time.isoformat()
            
            return (data, is_valid)
        
        return None
    
    def set(self, product_name: Optional[str], vendor_name: Optional[str],
            url: Optional[str], hash: Optional[str], assessment_data: Dict[str, Any]):
        """Store assessment in cache"""
        cache_key = self._generate_key(product_name, vendor_name, url, hash)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert datetime objects to strings for JSON serialization
        serializable_data = self._make_serializable(assessment_data)
        
        # Debug: Log the hash being stored
        stored_hash = assessment_data.get('hash')
        print(f"[Cache] Storing assessment with hash in cache_data: '{stored_hash}' (type: {type(stored_hash)})")
        
        # Serialize to JSON
        json_data = json.dumps(serializable_data)
        
        # Debug: Verify hash in serialized JSON
        parsed_back = json.loads(json_data)
        print(f"[Cache] Hash in serialized JSON: '{parsed_back.get('hash')}' (type: {type(parsed_back.get('hash'))})")
        
        cursor.execute("""
            INSERT OR REPLACE INTO assessments 
            (cache_key, entity_name, vendor_name, assessment_data, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            cache_key,
            assessment_data.get('entity_name', ''),
            assessment_data.get('vendor_name', ''),
            json_data,
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _make_serializable(self, obj: Any) -> Any:
        """Convert datetime objects to ISO format strings"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return obj
    
    def clear_old(self, days: Optional[int] = None):
        """Clear assessments older than specified days (defaults to TTL from config)"""
        if days is None:
            days = config.Config.CACHE_TTL_DAYS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM assessments 
            WHERE updated_at < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        
        return deleted
    
    def search(self, product_name: Optional[str] = None, vendor_name: Optional[str] = None,
               hash: Optional[str] = None, min_trust_score: Optional[int] = None,
               max_trust_score: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search cached assessments by product name, vendor, hash, or trust score range
        
        Args:
            product_name: Partial match on product name (case-insensitive)
            vendor_name: Partial match on vendor name (case-insensitive)
            hash: Partial match on hash (case-insensitive)
            min_trust_score: Minimum trust score (0-100)
            max_trust_score: Maximum trust score (0-100)
            limit: Maximum number of results to return
            
        Returns:
            List of assessment summaries with metadata
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build query dynamically
        conditions = []
        params = []
        
        if product_name:
            conditions.append("LOWER(entity_name) LIKE ?")
            params.append(f"%{product_name.lower()}%")
        
        if vendor_name:
            conditions.append("LOWER(vendor_name) LIKE ?")
            params.append(f"%{vendor_name.lower()}%")
        
        # Build base query
        query = "SELECT cache_key, entity_name, vendor_name, assessment_data, created_at, updated_at FROM assessments"
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor.execute(query, params)
            results = cursor.fetchall()
        except sqlite3.OperationalError as e:
            # Table might not exist - initialize it and try again
            print(f"[Cache] Table may not exist, initializing: {e}")
            conn.close()
            self._init_db()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
        
        conn.close()
        
        # Parse results and filter by hash and trust score
        assessments = []
        for row in results:
            cache_key, entity_name, vendor_name, assessment_data_json, created_at, updated_at = row
            
            try:
                data = json.loads(assessment_data_json)
            except json.JSONDecodeError:
                continue
            
            # Debug: Log hash from retrieved data
            raw_hash = data.get('hash')
            print(f"[Cache Search] Retrieved hash for {entity_name}: '{raw_hash}' (type: {type(raw_hash)})")
            
            # Filter by hash if provided
            if hash:
                # Check if hash exists in assessment data
                assessment_hash = data.get('hash') or ''
                if hash.lower() not in assessment_hash.lower():
                    continue
            
            # Get trust score
            trust_score = data.get('trust_score', {}).get('score', 50) if isinstance(data.get('trust_score'), dict) else 50
            
            # Filter by trust score range
            if min_trust_score is not None and trust_score < min_trust_score:
                continue
            if max_trust_score is not None and trust_score > max_trust_score:
                continue
            
            # Create summary
            # Get hash from cached data - handle None, empty string, etc.
            cached_hash = data.get('hash')
            print(f"[Cache Search] Processing hash for {entity_name}: raw='{cached_hash}', type={type(cached_hash)}")
            
            # Normalize: if hash is empty string, convert to None
            if cached_hash and isinstance(cached_hash, str) and cached_hash.strip():
                cached_hash = cached_hash.strip()
                print(f"[Cache Search] Hash normalized (string): '{cached_hash}'")
            elif cached_hash is None:
                cached_hash = None
                print(f"[Cache Search] Hash is None")
            elif cached_hash == '':
                cached_hash = None
                print(f"[Cache Search] Hash is empty string, converted to None")
            else:
                # Handle other types (shouldn't happen, but just in case)
                cached_hash = str(cached_hash).strip() if cached_hash else None
                print(f"[Cache Search] Hash converted from other type: '{cached_hash}'")
            
            summary = {
                'cache_key': cache_key,
                'entity_name': entity_name,
                'vendor_name': vendor_name,
                'trust_score': trust_score,
                'risk_level': data.get('trust_score', {}).get('risk_level', 'Unknown') if isinstance(data.get('trust_score'), dict) else 'Unknown',
                'category': data.get('category', 'Unknown'),
                'total_cves': data.get('security_posture', {}).get('cve_summary', {}).get('total_cves', 0) if isinstance(data.get('security_posture'), dict) else 0,
                'critical_cves': data.get('security_posture', {}).get('cve_summary', {}).get('critical_count', 0) if isinstance(data.get('security_posture'), dict) else 0,
                'cisa_kev_count': data.get('security_posture', {}).get('cve_summary', {}).get('cisa_kev_count', 0) if isinstance(data.get('security_posture'), dict) else 0,
                'created_at': created_at,
                'updated_at': updated_at,
                'is_cached': True,
                'hash': cached_hash  # This will be None if not present or empty
            }
            
            print(f"[Cache Search] Final hash in summary for {entity_name}: '{summary['hash']}' (type: {type(summary['hash'])})")
            assessments.append(summary)
        
        return assessments


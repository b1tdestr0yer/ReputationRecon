import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
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
        
        cursor.execute("""
            INSERT OR REPLACE INTO assessments 
            (cache_key, entity_name, vendor_name, assessment_data, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            cache_key,
            assessment_data.get('entity_name', ''),
            assessment_data.get('vendor_name', ''),
            json.dumps(serializable_data),
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


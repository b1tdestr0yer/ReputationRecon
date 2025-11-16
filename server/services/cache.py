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
        """Initialize the database schema and migrate old entries if needed"""
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
        
        # Migrate: Delete ALL cache entries that don't have pro_mode in their data
        # This ensures that only entries with proper pro_mode handling are kept
        # Since cache keys now include ai_mode, old entries without pro_mode in data
        # cannot be properly retrieved and should be deleted
        try:
            cursor.execute("""
                SELECT cache_key, assessment_data 
                FROM assessments
            """)
            old_entries = cursor.fetchall()
            
            invalidated_count = 0
            for cache_key, assessment_data_json in old_entries:
                should_delete = False
                reason = ""
                
                try:
                    data = json.loads(assessment_data_json)
                    # Check if pro_mode exists in the cached data and is a valid boolean
                    if 'pro_mode' not in data:
                        # This is an old entry without pro_mode - delete it
                        should_delete = True
                        reason = "no pro_mode in data"
                    elif not isinstance(data.get('pro_mode'), bool):
                        # Invalid pro_mode type - delete it
                        should_delete = True
                        reason = f"invalid pro_mode type: {type(data.get('pro_mode'))}"
                    else:
                        # Entry has valid pro_mode - keep it
                        pass
                except (json.JSONDecodeError, Exception) as e:
                    # Invalid JSON or other error - delete the entry
                    should_delete = True
                    reason = f"JSON error: {e}"
                
                if should_delete:
                    cursor.execute("DELETE FROM assessments WHERE cache_key = ?", (cache_key,))
                    invalidated_count += 1
                    print(f"[Cache Migration] Deleting cache entry: {cache_key[:16]}... (reason: {reason})")
            
            if invalidated_count > 0:
                print(f"[Cache Migration] ✓ Deleted {invalidated_count} invalid/old cache entries")
                conn.commit()
            else:
                print(f"[Cache Migration] ✓ All cache entries are valid")
        except Exception as e:
            print(f"[Cache Migration] ⚠ Error during migration: {e}")
            import traceback
            traceback.print_exc()
            # Don't fail if migration has issues, but log the error
        
        conn.commit()
        conn.close()
    
    def _generate_key(self, product_name: Optional[str], vendor_name: Optional[str], 
                     url: Optional[str], hash: Optional[str], pro_mode: bool) -> str:
        """
        Generate a deterministic cache key
        
        The cache key is based on (product_name, vendor_name, hash, pro_mode).
        At least one of product_name, vendor_name, or hash must be provided.
        pro_mode is required and distinguishes between Classic and PRO mode assessments.
        
        Args:
            product_name: Product name (can be None)
            vendor_name: Vendor name (can be None)
            url: URL (optional, for backward compatibility)
            hash: Hash value (can be None)
            pro_mode: True for PRO mode, False for Classic mode (REQUIRED)
            
        Returns:
            SHA256 hash of the sorted key parts
            
        Raises:
            ValueError: If all of product_name, vendor_name, and hash are None
        """
        # Validate that at least one identifier is provided
        if not product_name and not vendor_name and not hash:
            raise ValueError("At least one of product_name, vendor_name, or hash must be provided")
        
        key_parts = []
        if product_name:
            key_parts.append(f"product:{product_name.lower().strip()}")
        if vendor_name:
            key_parts.append(f"vendor:{vendor_name.lower().strip()}")
        if url:
            key_parts.append(f"url:{url.lower().strip()}")
        if hash:
            key_parts.append(f"hash:{hash.lower().strip()}")
        
        # ALWAYS include pro_mode in cache key (required parameter, no default)
        # This ensures Classic and PRO mode assessments are stored separately
        # Use explicit strings to make it clear and avoid any confusion
        ai_mode = "pro_mode" if pro_mode else "classic_mode"
        key_parts.append(f"ai_mode:{ai_mode}")
        
        # Sort key parts to ensure consistent key generation
        key_string = "|".join(sorted(key_parts))
        
        # Generate hash
        cache_key = hashlib.sha256(key_string.encode()).hexdigest()
        
        # Debug: Verify that Classic and PRO mode generate different keys
        if len(key_parts) > 1:  # Only log if we have identifier parts
            # Generate both keys to verify they're different
            classic_parts = [p for p in key_parts if not p.startswith("ai_mode:")] + ["ai_mode:classic_mode"]
            pro_parts = [p for p in key_parts if not p.startswith("ai_mode:")] + ["ai_mode:pro_mode"]
            classic_key = hashlib.sha256("|".join(sorted(classic_parts)).encode()).hexdigest()
            pro_key = hashlib.sha256("|".join(sorted(pro_parts)).encode()).hexdigest()
            if classic_key == pro_key:
                print(f"[Cache Key] ⚠ WARNING: Classic and PRO keys are identical! This should not happen!")
            elif pro_mode:
                print(f"[Cache Key] Generated PRO mode key (different from Classic): {cache_key[:16]}...")
            else:
                print(f"[Cache Key] Generated Classic mode key (different from PRO): {cache_key[:16]}...")
        
        return cache_key
    
    def get(self, product_name: Optional[str] = None, vendor_name: Optional[str] = None,
            url: Optional[str] = None, hash: Optional[str] = None, pro_mode: bool = False,
            ttl_days: Optional[int] = None) -> Optional[Tuple[Dict[str, Any], bool]]:
        """
        Retrieve cached assessment with expiration check
        
        Args:
            product_name: Product name (can be None)
            vendor_name: Vendor name (can be None)
            url: URL (optional)
            hash: Hash value (can be None)
            pro_mode: True for PRO mode, False for Classic mode
            ttl_days: Optional TTL override
            
        Returns:
            Tuple of (cached_data, is_valid) or None if not found
            is_valid indicates if cache is still within TTL
            
        Raises:
            ValueError: If all of product_name, vendor_name, and hash are None
        """
        # Validate inputs
        if not product_name and not vendor_name and not hash:
            raise ValueError("At least one of product_name, vendor_name, or hash must be provided")
        
        cache_key = self._generate_key(product_name, vendor_name, url, hash, pro_mode)
        print(f"[Cache] Looking up cache: pro_mode={pro_mode}, identifiers: product={bool(product_name)}, vendor={bool(vendor_name)}, hash={bool(hash)}, key={cache_key[:16]}...")
        
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
            try:
                data = json.loads(result[0])
            except json.JSONDecodeError as e:
                print(f"[Cache] ⚠ Invalid JSON in cache entry: {cache_key[:16]}..., deleting it")
                # Delete the corrupted entry
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM assessments WHERE cache_key = ?", (cache_key,))
                conn.commit()
                conn.close()
                return None
            
            updated_at_str = result[2]
            
            # STRICT validation: cached data MUST have pro_mode and it MUST match our request
            cached_pro_mode = data.get('pro_mode', None)
            
            # Check if pro_mode exists
            if cached_pro_mode is None:
                # Old entry without pro_mode - delete it and return None
                print(f"[Cache] ⚠ Found cache entry without pro_mode (should not happen after migration), deleting: {cache_key[:16]}...")
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM assessments WHERE cache_key = ?", (cache_key,))
                conn.commit()
                conn.close()
                return None
            
            # Check if pro_mode is a valid boolean
            if not isinstance(cached_pro_mode, bool):
                print(f"[Cache] ⚠ Found cache entry with invalid pro_mode type ({type(cached_pro_mode)}), deleting: {cache_key[:16]}...")
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM assessments WHERE cache_key = ?", (cache_key,))
                conn.commit()
                conn.close()
                return None
            
            # Check if pro_mode matches our request
            if cached_pro_mode != pro_mode:
                # Mismatch: cached entry is for different AI mode - don't return it
                # This should not happen if keys are generated correctly, but check anyway
                print(f"[Cache] ⚠ Cache entry AI mode mismatch: cached={cached_pro_mode}, requested={pro_mode}, key={cache_key[:16]}...")
                print(f"[Cache]    This should not happen - keys should be different. Deleting mismatched entry.")
                # Delete the mismatched entry to prevent future issues
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM assessments WHERE cache_key = ?", (cache_key,))
                conn.commit()
                conn.close()
                return None
            
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
            
            print(f"[Cache] ✓ Cache hit found (pro_mode={pro_mode}, valid={is_valid}, key={cache_key[:16]}...)")
            return (data, is_valid)
        
        return None
    
    def set(self, product_name: Optional[str], vendor_name: Optional[str],
            url: Optional[str], hash: Optional[str], assessment_data: Dict[str, Any], 
            pro_mode: bool = False):
        """
        Store assessment in cache
        
        Args:
            product_name: Product name (can be None)
            vendor_name: Vendor name (can be None)
            url: URL (optional)
            hash: Hash value (can be None)
            assessment_data: Assessment data to store
            pro_mode: True for PRO mode, False for Classic mode
            
        Raises:
            ValueError: If all of product_name, vendor_name, and hash are None
        """
        # Validate inputs
        if not product_name and not vendor_name and not hash:
            raise ValueError("At least one of product_name, vendor_name, or hash must be provided")
        
        cache_key = self._generate_key(product_name, vendor_name, url, hash, pro_mode)
        print(f"[Cache] Storing assessment with key for pro_mode={pro_mode}, key={cache_key[:16]}...")
        
        # Validate that assessment_data has pro_mode and it matches the parameter
        data_pro_mode = assessment_data.get('pro_mode', None)
        if data_pro_mode is None:
            # Force set pro_mode if it's missing (should not happen, but safety check)
            print(f"[Cache] ⚠ Assessment data missing pro_mode, setting it to {pro_mode}")
            assessment_data['pro_mode'] = pro_mode
        elif data_pro_mode != pro_mode:
            # Mismatch: fix it to match the parameter (should not happen, but safety check)
            print(f"[Cache] ⚠ Assessment data pro_mode ({data_pro_mode}) doesn't match parameter ({pro_mode}), fixing it")
            assessment_data['pro_mode'] = pro_mode
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Convert datetime objects to strings for JSON serialization
        serializable_data = self._make_serializable(assessment_data)
        
        # Debug: Log the hash and pro_mode being stored
        stored_hash = assessment_data.get('hash')
        stored_pro_mode = serializable_data.get('pro_mode')
        print(f"[Cache] Storing assessment: hash='{stored_hash}' (type: {type(stored_hash)}), pro_mode={stored_pro_mode} (type: {type(stored_pro_mode)})")
        
        # Serialize to JSON
        json_data = json.dumps(serializable_data)
        
        # Debug: Verify hash and pro_mode in serialized JSON
        parsed_back = json.loads(json_data)
        print(f"[Cache] Verification: hash='{parsed_back.get('hash')}' (type: {type(parsed_back.get('hash'))}), pro_mode={parsed_back.get('pro_mode')} (type: {type(parsed_back.get('pro_mode'))})")
        
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
            
            # Get pro_mode from cached data (default to False for backwards compatibility)
            pro_mode = data.get('pro_mode', False)
            
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
                'hash': cached_hash,  # This will be None if not present or empty
                'pro_mode': pro_mode  # Include pro_mode in search results
            }
            
            print(f"[Cache Search] Final hash in summary for {entity_name}: '{summary['hash']}' (type: {type(summary['hash'])})")
            assessments.append(summary)
        
        return assessments


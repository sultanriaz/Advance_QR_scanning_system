"""
reputation.py
--------------
<<<<<<< HEAD
Professional domain reputation system with caching and auto-reload
"""

import os
import time
import threading
import logging
from pathlib import Path
from typing import Tuple, List, Set, Dict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# -----------------------------
# Configuration
# -----------------------------
class ReputationConfig:
    """Reputation system configuration"""
    
    REPUTATION_FILE_PATH = Path(__file__).resolve().parent
    BLACKLIST_FILE = REPUTATION_FILE_PATH / "blacklist.txt"
    WHITELIST_FILE = REPUTATION_FILE_PATH / "whitelist.txt"
    
    # Scoring weights
    BLACKLIST_PENALTY = 40
    WHITELIST_BONUS = -25
    
    # Cache settings
    CACHE_TTL_SECONDS = 300  # 5 minutes
    AUTO_RELOAD_INTERVAL_SECONDS = 600  # 10 minutes
    
    # Additional reputation sources (can be extended)
    ENABLE_PATTERN_MATCHING = True
    ENABLE_EXPIRY = True

# -----------------------------
# Reputation Manager
# -----------------------------
class ReputationManager:
    """Thread-safe reputation management with caching and auto-reload"""
    
    def __init__(self):
        self._blacklist: Set[str] = set()
        self._whitelist: Set[str] = set()
        self._pattern_blacklist: List[str] = []
        self._cache: Dict[str, Tuple[int, List[str], float]] = {}
        self._last_reload = 0
        self._lock = threading.RLock()
        
        # Load initial lists
        self._load_lists()
        
        # Start auto-reload thread
        self._start_auto_reload()
    
    def _load_lists(self):
        """Load blacklist and whitelist from files"""
        with self._lock:
            # Load blacklist
            if ReputationConfig.BLACKLIST_FILE.exists():
                with open(ReputationConfig.BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                    self._blacklist = {
                        line.strip().lower() 
                        for line in f 
                        if line.strip() and not line.startswith('#')
                    }
                logger.info(f"Loaded {len(self._blacklist)} domains to blacklist")
            else:
                logger.warning(f"Blacklist file not found: {ReputationConfig.BLACKLIST_FILE}")
                self._blacklist = set()
            
            # Load whitelist
            if ReputationConfig.WHITELIST_FILE.exists():
                with open(ReputationConfig.WHITELIST_FILE, 'r', encoding='utf-8') as f:
                    self._whitelist = {
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith('#')
                    }
                logger.info(f"Loaded {len(self._whitelist)} domains to whitelist")
            else:
                logger.warning(f"Whitelist file not found: {ReputationConfig.WHITELIST_FILE}")
                self._whitelist = set()
            
            # Load pattern-based blacklist (optional)
            pattern_file = ReputationConfig.REPUTATION_FILE_PATH / "patterns.txt"
            if pattern_file.exists():
                with open(pattern_file, 'r', encoding='utf-8') as f:
                    self._pattern_blacklist = [
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith('#')
                    ]
                logger.info(f"Loaded {len(self._pattern_blacklist)} blacklist patterns")
            
            self._last_reload = time.time()
    
    def _start_auto_reload(self):
        """Start background thread for automatic list reloading"""
        def reload_worker():
            while True:
                time.sleep(ReputationConfig.AUTO_RELOAD_INTERVAL_SECONDS)
                try:
                    self._load_lists()
                    logger.debug("Auto-reloaded reputation lists")
                except Exception as e:
                    logger.error(f"Auto-reload failed: {e}")
        
        reload_thread = threading.Thread(target=reload_worker, daemon=True)
        reload_thread.start()
    
    def _is_cache_valid(self, domain: str) -> bool:
        """Check if cached entry is still valid"""
        if domain in self._cache:
            _, _, timestamp = self._cache[domain]
            return (time.time() - timestamp) < ReputationConfig.CACHE_TTL_SECONDS
        return False
    
    def _matches_pattern(self, domain: str) -> bool:
        """Check if domain matches any blacklist pattern"""
        if not ReputationConfig.ENABLE_PATTERN_MATCHING:
            return False
        
        domain_lower = domain.lower()
        for pattern in self._pattern_blacklist:
            if pattern.startswith('*.'):
                # Wildcard subdomain pattern
                suffix = pattern[2:]
                if domain_lower.endswith(suffix):
                    return True
            elif pattern in domain_lower:
                return True
        return False
    
    def get_reputation(self, domain: str) -> Tuple[int, List[str]]:
        """
        Get reputation adjustment for a domain
        
        Returns:
            (adjustment_score, reasons)
        """
        if not domain:
            return 0, []
        
        domain_lower = domain.lower()
        
        # Check cache
        with self._lock:
            if self._is_cache_valid(domain_lower):
                adjustment, reasons, _ = self._cache[domain_lower]
                return adjustment, reasons.copy()
        
        # Perform reputation check
        adjustment = 0
        reasons = []
        
        # Check exact blacklist match
        if domain_lower in self._blacklist:
            adjustment = ReputationConfig.BLACKLIST_PENALTY
            reasons.append("🚫 Domain is blacklisted")
            logger.warning(f"Blacklisted domain detected: {domain}")
        
        # Check pattern match
        elif self._matches_pattern(domain_lower):
            adjustment = ReputationConfig.BLACKLIST_PENALTY // 2
            reasons.append("⚠️ Domain matches blacklist pattern")
            logger.info(f"Pattern match for domain: {domain}")
        
        # Check whitelist
        elif domain_lower in self._whitelist:
            adjustment = ReputationConfig.WHITELIST_BONUS
            reasons.append("✅ Domain is whitelisted")
        
        # Cache the result
        with self._lock:
            self._cache[domain_lower] = (adjustment, reasons, time.time())
        
        return adjustment, reasons
    
    def reload(self) -> bool:
        """Manually reload reputation lists"""
        try:
            self._load_lists()
            # Clear cache on reload
            with self._lock:
                self._cache.clear()
            logger.info("Reputation lists reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reload reputation lists: {e}")
            return False
    
    def add_to_blacklist(self, domain: str) -> bool:
        """Add domain to blacklist dynamically"""
        domain_lower = domain.lower()
        with self._lock:
            self._blacklist.add(domain_lower)
            # Also write to file
            try:
                with open(ReputationConfig.BLACKLIST_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"{domain_lower}\n")
                logger.info(f"Added {domain} to blacklist")
                return True
            except Exception as e:
                logger.error(f"Failed to write to blacklist: {e}")
                return False
    
    def add_to_whitelist(self, domain: str) -> bool:
        """Add domain to whitelist dynamically"""
        domain_lower = domain.lower()
        with self._lock:
            self._whitelist.add(domain_lower)
            # Also write to file
            try:
                with open(ReputationConfig.WHITELIST_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"{domain_lower}\n")
                logger.info(f"Added {domain} to whitelist")
                return True
            except Exception as e:
                logger.error(f"Failed to write to whitelist: {e}")
                return False
    
    def get_stats(self) -> Dict:
        """Get reputation system statistics"""
        with self._lock:
            return {
                "blacklist_size": len(self._blacklist),
                "whitelist_size": len(self._whitelist),
                "pattern_count": len(self._pattern_blacklist),
                "cache_size": len(self._cache),
                "last_reload": datetime.fromtimestamp(self._last_reload).isoformat()
            }

# Initialize global reputation manager
_reputation_manager = ReputationManager()

# -----------------------------
# Public API Functions
# -----------------------------

def get_reputation_adjustment(domain: str) -> Tuple[int, List[str]]:
    """
    Get reputation adjustment for a domain
    
    Returns:
        (score_adjustment, reasons)
    """
    return _reputation_manager.get_reputation(domain)

def reload_lists() -> bool:
    """Reload reputation lists"""
    return _reputation_manager.reload()

def add_blacklist(domain: str) -> bool:
    """Add domain to blacklist"""
    return _reputation_manager.add_to_blacklist(domain)

def add_whitelist(domain: str) -> bool:
    """Add domain to whitelist"""
    return _reputation_manager.add_to_whitelist(domain)

def get_reputation_stats() -> Dict:
    """Get reputation system statistics"""
    return _reputation_manager.get_stats()

# For backward compatibility
def is_blacklisted(domain: str) -> bool:
    """Legacy function for compatibility"""
    adjustment, _ = get_reputation_adjustment(domain)
    return adjustment >= ReputationConfig.BLACKLIST_PENALTY

def is_whitelisted(domain: str) -> bool:
    """Legacy function for compatibility"""
    adjustment, _ = get_reputation_adjustment(domain)
    return adjustment <= ReputationConfig.WHITELIST_BONUS



from pathlib import Path

# -----------------------------
# File Paths
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent
BLACKLIST_FILE = BASE_DIR / "blacklist.txt"
WHITELIST_FILE = BASE_DIR / "whitelist.txt"


# -----------------------------
# Helper Functions
# -----------------------------
def load_list(file_path: Path) -> set:
    """
    Load domains from a text file into a set.

    Each line should contain a single domain.
    Returns an empty set if file does not exist.
    """
    if not file_path.exists():
        print(f"[Warning] File not found: {file_path}")
        return set()

    with open(file_path, "r") as f:
        # Strip whitespace, ignore empty lines, convert to lowercase
        return {line.strip().lower() for line in f if line.strip()}


# -----------------------------
# Load Lists at Startup
# -----------------------------
BLACKLIST = load_list(BLACKLIST_FILE)
WHITELIST = load_list(WHITELIST_FILE)


# -----------------------------
# Public API
# -----------------------------
def check_blacklist(domain: str) -> bool:
    """
    Return True if the domain is blacklisted.
    """
    if not domain:
        return False
    return domain.lower() in BLACKLIST


def check_whitelist(domain: str) -> bool:
    """
    Return True if the domain is whitelisted.
    """
    if not domain:
        return False
    return domain.lower() in WHITELIST


def add_to_blacklist(domain: str):
    """
    Append a domain to blacklist file and refresh set.
    """
    domain = domain.lower().strip()
    if domain and domain not in BLACKLIST:
        with open(BLACKLIST_FILE, "a") as f:
            f.write(domain + "\n")
        BLACKLIST.add(domain)


def add_to_whitelist(domain: str):
    
    
    domain = domain.lower().strip()
    if domain and domain not in WHITELIST:
        with open(WHITELIST_FILE, "a") as f:
            f.write(domain + "\n")
        WHITELIST.add(domain)

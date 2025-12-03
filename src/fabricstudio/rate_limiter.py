"""Rate limiter for Fabric host API requests to prevent exceeding rate limits"""
import time
import threading
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class FabricHostRateLimiter:
    """
    Rate limiter that tracks requests per Fabric host to prevent exceeding
    the API rate limit (500 requests per 60 seconds per host).
    """
    
    def __init__(self, max_requests: int = 500, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_times: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._cleanup_interval = 300  # Clean up old entries every 5 minutes
        self._last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Remove old request timestamps that are outside the window"""
        now = time.time()
        cutoff = now - self.window_seconds
        
        with self._lock:
            for host in list(self._request_times.keys()):
                self._request_times[host] = [
                    ts for ts in self._request_times[host] if ts > cutoff
                ]
                # Remove empty entries
                if not self._request_times[host]:
                    del self._request_times[host]
    
    def wait_if_needed(self, fabric_host: str) -> float:
        """
        Check if we need to wait before making a request to the given host.
        Returns the number of seconds to wait (0 if no wait needed).
        
        Args:
            fabric_host: The Fabric host address
            
        Returns:
            Number of seconds to wait before making the request
        """
        now = time.time()
        
        # Periodic cleanup
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_entries()
            self._last_cleanup = now
        
        with self._lock:
            # Get or create request timestamps for this host
            if fabric_host not in self._request_times:
                self._request_times[fabric_host] = []
            
            # Remove old timestamps outside the window
            cutoff = now - self.window_seconds
            self._request_times[fabric_host] = [
                ts for ts in self._request_times[fabric_host] if ts > cutoff
            ]
            
            # Check if we're at the limit
            if len(self._request_times[fabric_host]) >= self.max_requests:
                # Calculate how long to wait
                oldest_request = min(self._request_times[fabric_host])
                wait_time = (oldest_request + self.window_seconds) - now
                if wait_time > 0:
                    logger.debug(
                        "Rate limit reached for %s. Waiting %.2f seconds",
                        fabric_host, wait_time
                    )
                    return wait_time
            
            # Add current request timestamp
            self._request_times[fabric_host].append(now)
            return 0.0
    
    def record_request(self, fabric_host: str):
        """
        Record that a request was made to the given host.
        This is called automatically by wait_if_needed, but can be called
        manually if you want to record a request without waiting.
        """
        now = time.time()
        
        with self._lock:
            if fabric_host not in self._request_times:
                self._request_times[fabric_host] = []
            
            # Remove old timestamps
            cutoff = now - self.window_seconds
            self._request_times[fabric_host] = [
                ts for ts in self._request_times[fabric_host] if ts > cutoff
            ]
            
            # Add current request timestamp
            self._request_times[fabric_host].append(now)
    
    def get_remaining_capacity(self, fabric_host: str) -> int:
        """
        Get the number of requests that can be made to the given host
        without waiting.
        
        Args:
            fabric_host: The Fabric host address
            
        Returns:
            Number of requests that can be made immediately
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        with self._lock:
            if fabric_host not in self._request_times:
                return self.max_requests
            
            # Remove old timestamps
            self._request_times[fabric_host] = [
                ts for ts in self._request_times[fabric_host] if ts > cutoff
            ]
            
            return max(0, self.max_requests - len(self._request_times[fabric_host]))


# Global rate limiter instance
_rate_limiter = FabricHostRateLimiter(max_requests=500, window_seconds=60)


def wait_for_rate_limit(fabric_host: str) -> float:
    """
    Wait if necessary to respect rate limits for the given Fabric host.
    
    NOTE: Rate limiting is disabled. This function is a no-op.
    
    Args:
        fabric_host: The Fabric host address
        
    Returns:
        Number of seconds waited (always 0)
    """
    # Rate limiting disabled - no wait
    return 0.0


def record_api_request(fabric_host: str):
    """
    Record that an API request was made to the given host.
    
    NOTE: Rate limiting is disabled. This function is a no-op.
    
    Args:
        fabric_host: The Fabric host address
    """
    # Rate limiting disabled - no recording
    pass


def get_remaining_capacity(fabric_host: str) -> int:
    """
    Get the number of requests that can be made to the given host without waiting.
    
    Args:
        fabric_host: The Fabric host address
        
    Returns:
        Number of requests that can be made immediately
    """
    return _rate_limiter.get_remaining_capacity(fabric_host)


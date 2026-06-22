"""
Simple in-memory rate limiter for decrypt endpoint protection.

Prevents brute-force attacks by limiting password attempts per IP address.
"""

import time
from collections import defaultdict
from typing import Tuple


class RateLimiter:
    """
    Token bucket rate limiter keyed by client IP.
    
    Configuration:
    - max_requests: Maximum requests per time window
    - time_window_seconds: Time window duration
    """
    
    def __init__(self, max_requests: int = 30, time_window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Default: 30 requests per 60 seconds = 1 request every 2 seconds
        Prevents brute-force: ~1,800 attempts/minute with single client
        Legitimate users (correct password on first try): 1 request, always allowed
        """
        self.max_requests = max_requests
        self.time_window_seconds = time_window_seconds
        
        # Track requests per IP: {ip: [(timestamp, count), ...]}
        self._requests = defaultdict(list)
        self._cleanup_interval = 300  # Clean old records every 5 minutes
        self._last_cleanup = time.time()
    
    def is_allowed(self, client_ip: str) -> Tuple[bool, dict]:
        """
        Check if request from client_ip is allowed.
        
        Returns:
        - (allowed: bool, info: dict)
          - allowed: True if request is within rate limit
          - info: Contains current_count, limit, reset_time_seconds
        """
        now = time.time()
        
        # Periodic cleanup
        if now - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_records(now)
        
        # Get requests from this IP in current window
        window_start = now - self.time_window_seconds
        
        # Remove old requests outside window
        if client_ip in self._requests:
            self._requests[client_ip] = [
                (ts, count) for ts, count in self._requests[client_ip]
                if ts > window_start
            ]
        
        # Count total requests in current window
        current_count = sum(count for _, count in self._requests[client_ip])
        
        # Determine if allowed
        allowed = current_count < self.max_requests
        
        if allowed:
            # Add/update current request
            if self._requests[client_ip]:
                # Increment last request count
                ts, count = self._requests[client_ip][-1]
                if ts == now:
                    self._requests[client_ip][-1] = (ts, count + 1)
                else:
                    self._requests[client_ip].append((now, 1))
            else:
                self._requests[client_ip].append((now, 1))
        
        # Calculate reset time (when oldest request leaves the window)
        reset_time = None
        if self._requests[client_ip]:
            oldest_ts = self._requests[client_ip][0][0]
            reset_time = max(0, oldest_ts + self.time_window_seconds - now)
        
        return allowed, {
            "current_count": current_count,
            "limit": self.max_requests,
            "window_seconds": self.time_window_seconds,
            "reset_seconds": reset_time
        }
    
    def _cleanup_old_records(self, now: float) -> None:
        """Remove IPs with no recent requests."""
        cutoff = now - (self.time_window_seconds * 2)
        to_remove = [
            ip for ip, requests in self._requests.items()
            if not requests or requests[-1][0] < cutoff
        ]
        for ip in to_remove:
            del self._requests[ip]
        self._last_cleanup = now

"""
Constant-time response utilities to prevent timing side-channel leaks.

In real HE, all responses should take similar time regardless of:
- Whether password is correct
- Whether credential is real or fake
- What the decoded message is
"""

import time
import asyncio


class ConstantTimeWrapper:
    """Add constant artificial delay to equalize response times."""
    
    TARGET_RESPONSE_TIME_MS = 100  # Target response time in milliseconds
    
    @staticmethod
    async def wrap(coroutine, min_delay_ms: int | None = None):
        """
        Execute coroutine and pad with delay to reach target time.
        
        Ensures all responses take at least min_delay_ms to return,
        preventing timing attacks.
        """
        delay_ms = min_delay_ms or ConstantTimeWrapper.TARGET_RESPONSE_TIME_MS
        
        start = time.time()
        result = await coroutine
        elapsed_ms = (time.time() - start) * 1000
        
        remaining_ms = delay_ms - elapsed_ms
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000)
        
        return result

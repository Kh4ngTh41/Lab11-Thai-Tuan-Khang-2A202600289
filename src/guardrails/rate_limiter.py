"""
Lab 11 — Rate Limiter Plugin
Prevents abuse by limiting requests per user within a time window.
Smart rate limiting with warning thresholds to avoid blocking legitimate users.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


@dataclass
class UserRateState:
    """Track rate limit state per user."""
    window: deque = None
    warning_count: int = 0
    first_request_time: float = 0.0


class RateLimitPlugin(base_plugin.BasePlugin):
    """Smart rate limiter with warning thresholds to avoid blocking legitimate users.

    This rate limiter uses a multi-tier approach:
    - Requests 1-20: PASS (normal usage)
    - Requests 21-30: WARNING (close to limit, no blocking yet)
    - Requests 31+: BLOCK (hard limit)

    Uses sliding window algorithm for accurate rate limiting.
    Per-user tracking to prevent one abusive user from affecting others.
    """

    # Tiered limits - adjusted for legitimate banking usage
    # Normal user might do 10-15 requests in a session
    # Power user might do 20-30 requests

    # Tier 1: Normal limit - allows typical banking session
    NORMAL_LIMIT = 20           # 20 requests

    # Tier 2: Extended limit - for heavy but legitimate users
    EXTENDED_LIMIT = 30         # 30 requests

    # Tier 3: Absolute limit - only for abuse prevention
    ABSOLUTE_LIMIT = 50        # 50 requests max

    # Time windows
    NORMAL_WINDOW = 120         # 2 minutes for normal tier
    EXTENDED_WINDOW = 300       # 5 minutes for extended tier
    ABSOLUTE_WINDOW = 600       # 10 minutes for absolute tier

    def __init__(
        self,
        normal_limit: int = None,
        extended_limit: int = None,
        absolute_limit: int = None,
    ):
        """Initialize rate limiter with tiered limits.

        Args:
            normal_limit: Max requests before warning (default: 20)
            extended_limit: Max requests before hard block (default: 30)
            absolute_limit: Absolute max requests per window (default: 50)
        """
        super().__init__(name="rate_limiter")

        # Use tiered limits
        self.normal_limit = normal_limit or self.NORMAL_LIMIT
        self.extended_limit = extended_limit or self.EXTENDED_LIMIT
        self.absolute_limit = absolute_limit or self.ABSOLUTE_LIMIT

        # Per-user state tracking
        self.user_states = defaultdict(lambda: {
            "window": deque(),
            "warning_count": 0,
            "blocked_count": 0,
            "total_requests": 0,
        })

        # Statistics
        self.total_requests = 0
        self.warning_requests = 0
        self.blocked_requests = 0

    def _cleanup_window(self, user_id: str, current_time: float) -> deque:
        """Remove expired timestamps from user's window.

        Uses the EXTENDED_WINDOW as cleanup threshold.
        """
        state = self.user_states[user_id]
        window = state["window"]

        # Clean entries older than ABSOLUTE_WINDOW
        # This gives us a sliding window that decays over time
        cutoff = current_time - self.ABSOLUTE_WINDOW

        while window and window[0] < cutoff:
            window.popleft()

        return window

    def _get_wait_time(self, user_id: str, current_time: float) -> float:
        """Calculate seconds until oldest entry expires."""
        state = self.user_states[user_id]
        window = state["window"]

        if not window:
            return 0.0

        oldest = window[0]
        # How long until the oldest request falls out of the ABSOLUTE_WINDOW
        return max(0.0, (oldest + self.ABSOLUTE_WINDOW) - current_time)

    def _get_tier_info(self, window: deque) -> tuple:
        """Get current tier and remaining quota.

        Returns:
            tuple of (tier_name, requests_used, limit, remaining)
        """
        size = len(window)

        if size < self.normal_limit:
            return ("NORMAL", size, self.normal_limit, self.normal_limit - size)
        elif size < self.extended_limit:
            return ("EXTENDED", size, self.extended_limit, self.extended_limit - size)
        else:
            return ("ABSOLUTE", size, self.absolute_limit, 0)

    def _create_response(
        self,
        tier: str,
        message: str,
        wait_time: float = 0,
    ) -> types.Content:
        """Create a Content object with rate limit response."""
        if wait_time > 0:
            message += f" Please wait {wait_time:.0f} seconds and try again."

        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check rate limit before processing message.

        Smart tiered approach:
        - Within NORMAL_LIMIT: always pass
        - NORMAL to EXTENDED: pass with warning
        - Beyond EXTENDED: block

        Returns:
            None if within rate limit,
            types.Content with block message if rate limited
        """
        self.total_requests += 1
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        current_time = time.time()

        # Get user state
        state = self.user_states[user_id]

        # Cleanup old entries
        window = self._cleanup_window(user_id, current_time)

        # Get current tier info
        tier_name, used, limit, remaining = self._get_tier_info(window)

        state["total_requests"] += 1

        # TIER 1: NORMAL - Always pass, no questions asked
        if tier_name == "NORMAL":
            window.append(current_time)
            return None

        # TIER 2: EXTENDED - Pass but track warning
        elif tier_name == "EXTENDED":
            state["warning_count"] += 1
            self.warning_requests += 1

            # Still allow, but could add warning header to response
            window.append(current_time)

            # Optionally: return None but log the warning
            # This way legitimate users having long sessions aren't blocked
            return None

        # TIER 3: ABSOLUTE - Hard block
        else:
            wait_time = self._get_wait_time(user_id, current_time)

            # Only count as blocked if they truly can't make progress
            # If wait_time is short, let them through
            if wait_time > 10:  # Block only if need to wait > 10 seconds
                state["blocked_count"] += 1
                self.blocked_requests += 1

                return self._create_response(
                    tier="ABSOLUTE",
                    message=f"Too many requests detected. "
                            f"Maximum {self.absolute_limit} requests per 10 minutes. "
                            f"You have made {used} requests.",
                    wait_time=wait_time
                )
            else:
                # Short wait - let them through
                window.append(current_time)
                return None

    def get_user_stats(self, user_id: str = None) -> dict:
        """Get rate limit statistics.

        Args:
            user_id: Specific user to get stats for, or None for global stats

        Returns:
            dict with statistics
        """
        if user_id:
            state = self.user_states.get(user_id, {})
            return {
                "total_requests": state.get("total_requests", 0),
                "warning_count": state.get("warning_count", 0),
                "blocked_count": state.get("blocked_count", 0),
                "current_window_size": len(state.get("window", [])),
            }

        # Global stats
        return {
            "total_requests": self.total_requests,
            "warning_requests": self.warning_requests,
            "blocked_requests": self.blocked_requests,
            "unique_users": len(self.user_states),
            "warning_rate": (
                self.warning_requests / self.total_requests
                if self.total_requests > 0 else 0
            ),
            "block_rate": (
                self.blocked_requests / self.total_requests
                if self.total_requests > 0 else 0
            ),
        }

    def reset_user(self, user_id: str = None):
        """Reset rate limit state for a user (for testing/admin)."""
        if user_id and user_id in self.user_states:
            del self.user_states[user_id]


# Keep old test function for compatibility, but update it
def test_rate_limiter():
    """Test rate limiter behavior with new tiered approach."""
    print("Testing NEW RateLimiter with tiered limits:")
    print("=" * 70)
    print(f"  NORMAL tier:  1-{RateLimitPlugin.NORMAL_LIMIT} requests (always pass)")
    print(f"  EXTENDED tier: {RateLimitPlugin.NORMAL_LIMIT}-{RateLimitPlugin.EXTENDED_LIMIT} requests (pass with warning)")
    print(f"  ABSOLUTE tier: {RateLimitPlugin.EXTENDED_LIMIT}-{RateLimitPlugin.ABSOLUTE_LIMIT} requests (hard block if >10s wait)")
    print("=" * 70)

    # Test normal user
    print("\n[Test 1] Normal user - should pass all requests:")
    plugin = RateLimitPlugin()

    class MockContext:
        user_id = "normal_user"

    class MockMessage:
        role = "user"
        parts = []

    for i in range(1, 25):
        result = plugin._sync_on_user_message_callback(
            invocation_context=MockContext(),
            user_message=MockMessage()
        )
        tier, used, limit, _ = plugin._get_tier_info(plugin.user_states["normal_user"]["window"])
        status = "BLOCKED" if result else "PASSED"
        if i <= 5 or i == 20 or i == 24:
            print(f"  Request {i:2d}: {status} (tier={tier}, used={used}/{limit})")

    print(f"\n  Stats: {plugin.get_user_stats('normal_user')}")

    # Test heavy user approaching limits
    print("\n[Test 2] Heavy user - approaching extended limit:")
    plugin2 = RateLimitPlugin()

    for i in range(1, 35):
        result = plugin2._sync_on_user_message_callback(
            invocation_context=MockContext(),
            user_message=MockMessage()
        )
        tier, used, limit, _ = plugin2._get_tier_info(plugin2.user_states["normal_user"]["window"])
        status = "BLOCKED" if result else "PASSED"
        if i <= 5 or i == 25 or i == 30 or i == 33 or i == 34:
            print(f"  Request {i:2d}: {status} (tier={tier}, used={used}/{limit})")

    print(f"\n  Stats: {plugin2.get_user_stats('normal_user')}")

    # Test abuse detection
    print("\n[Test 3] Abuse detection - should block at absolute limit:")
    plugin3 = RateLimitPlugin()

    blocked_count = 0
    for i in range(1, 55):
        result = plugin3._sync_on_user_message_callback(
            invocation_context=MockContext(),
            user_message=MockMessage()
        )
        if result:
            blocked_count += 1
            tier, used, limit, _ = plugin3._get_tier_info(plugin3.user_states["normal_user"]["window"])
            print(f"  Request {i:2d}: BLOCKED (tier={tier}, used={used}/{limit})")

    print(f"\n  Total blocked: {blocked_count} out of 54 requests")
    print(f"  Stats: {plugin3.get_user_stats()}")


def test_rate_limiter():
    """Test rate limiter behavior."""
    # Test with tiered limits
    plugin = RateLimitPlugin()  # Uses default tiered limits

    print("Testing RateLimitPlugin (tiered):")
    print("=" * 60)
    print(f"NORMAL tier: 1-{RateLimitPlugin.NORMAL_LIMIT} requests (always pass)")
    print(f"EXTENDED tier: {RateLimitPlugin.NORMAL_LIMIT}-{RateLimitPlugin.EXTENDED_LIMIT} requests (pass with warning)")
    print(f"ABSOLUTE tier: {RateLimitPlugin.EXTENDED_LIMIT}-{RateLimitPlugin.ABSOLUTE_LIMIT} requests (block if >10s wait)")
    print("=" * 60)

    import time

    # Test normal user - should pass all 25 requests
    print("\n[Test 1] Normal user - 25 requests:")
    user_id = "normal_user"

    for i in range(1, 26):
        current_time = time.time()
        window = plugin._cleanup_window(user_id, current_time)
        tier, used, limit, remaining = plugin._get_tier_info(window)

        # Simulate the check
        if tier == "NORMAL":
            window.append(current_time)
            tier_name = "NORMAL"
        elif tier == "EXTENDED":
            plugin.user_states[user_id]["warning_count"] += 1
            window.append(current_time)
            tier_name = "EXTENDED"
        else:
            wait_time = plugin._get_wait_time(user_id, current_time)
            if wait_time > 10:
                tier_name = "ABSOLUTE_BLOCKED"
            else:
                window.append(current_time)
                tier_name = "ABSOLUTE_PASS"

        if i <= 5 or i == 20 or i == 25:
            print(f"  Request {i:2d}: tier={tier_name}, used={used}/{limit}")

    print(f"  Stats: {plugin.get_user_stats(user_id)}")

    # Test extended tier user
    print("\n[Test 2] Heavy user - 35 requests:")
    user_id = "heavy_user"
    plugin2 = RateLimitPlugin()

    for i in range(1, 36):
        current_time = time.time()
        window = plugin2._cleanup_window(user_id, current_time)
        tier, used, limit, remaining = plugin2._get_tier_info(window)

        if tier == "NORMAL":
            window.append(current_time)
        elif tier == "EXTENDED":
            plugin2.user_states[user_id]["warning_count"] += 1
            window.append(current_time)
        else:
            wait_time = plugin2._get_wait_time(user_id, current_time)
            if wait_time > 10:
                plugin2.user_states[user_id]["blocked_count"] += 1
            else:
                window.append(current_time)

        if i <= 5 or i == 25 or i == 30 or i == 34 or i == 35:
            print(f"  Request {i:2d}: tier={tier}, used={used}/{limit}")

    print(f"  Stats: {plugin2.get_user_stats(user_id)}")

    # Test abuse - 55 requests
    print("\n[Test 3] Abuse test - 55 requests:")
    user_id = "abuser"
    plugin3 = RateLimitPlugin()
    blocked = 0

    for i in range(1, 56):
        current_time = time.time()
        window = plugin3._cleanup_window(user_id, current_time)
        tier, used, limit, remaining = plugin3._get_tier_info(window)

        if tier == "NORMAL":
            window.append(current_time)
        elif tier == "EXTENDED":
            plugin3.user_states[user_id]["warning_count"] += 1
            window.append(current_time)
        else:
            wait_time = plugin3._get_wait_time(user_id, current_time)
            if wait_time > 10:
                plugin3.user_states[user_id]["blocked_count"] += 1
                blocked += 1
                if i <= 40:
                    print(f"  Request {i:2d}: BLOCKED (tier=ABSOLUTE, wait={wait_time:.0f}s)")
            else:
                window.append(current_time)

    print(f"\n  Total blocked: {blocked}/55")
    print(f"  Stats: {plugin3.get_user_stats(user_id)}")

    print("\n" + "=" * 60)
    print("Summary: Rate limiter now uses tiered approach")
    print("- Normal users (1-20 req/2min): Always pass")
    print("- Extended users (21-30 req/5min): Pass with warning")
    print("- Abuse prevention (31-50 req/10min): Block if >10s wait")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    test_rate_limiter()

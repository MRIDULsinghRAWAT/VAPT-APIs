"""
Rate Limiting Attack Module

Strategy:
  1. Identify auth-sensitive endpoints (login, OTP, password reset)
  2. Send a burst of N requests in rapid succession
  3. If no 429/throttling response after N requests → rate limiting absent

Can run off the spec alone — no two-account setup needed.
"""

from typing import List

from app.attacks.base import AttackResult, BaseAttackModule


class RateLimitAttackModule(BaseAttackModule):
    """Detect missing Rate Limiting on sensitive endpoints."""

    @property
    def name(self) -> str:
        return "Rate Limit Probe"

    @property
    def category(self) -> str:
        return "RateLimiting"

    async def run(self, **kwargs) -> List[AttackResult]:
        """
        TODO (Phase 2): Implement Rate Limit detection.

        Expected kwargs:
          - endpoints: List[EndpointInfo] (filtered to auth/sensitive routes)
          - base_url: str
          - burst_count: int (default: 50)
          - auth_creds: AuthCredentials (optional)

        Algorithm:
          1. For each sensitive endpoint (login, register, otp, reset):
             a. Fire `burst_count` requests as fast as possible
             b. Track response codes
             c. If zero 429s received → vulnerable (no rate limiting)
             d. If 429s appear → note the threshold
        """
        return []

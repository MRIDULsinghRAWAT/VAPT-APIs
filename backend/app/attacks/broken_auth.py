"""
Broken Authentication Attack Module

Tests:
  1. JWT signature bypass (alg:none, weak secret brute-force)
  2. Token expiry validation (expired tokens still accepted?)
  3. Missing authentication on sensitive routes
  4. Default / weak credentials
"""

from typing import List

from app.attacks.base import AttackResult, BaseAttackModule


class BrokenAuthAttackModule(BaseAttackModule):
    """Detect Broken Authentication vulnerabilities."""

    @property
    def name(self) -> str:
        return "Broken Auth Detector"

    @property
    def category(self) -> str:
        return "BrokenAuth"

    async def run(self, **kwargs) -> List[AttackResult]:
        """
        TODO (Phase 2): Implement Broken Auth detection.

        Expected kwargs:
          - endpoints: List[EndpointInfo]
          - base_url: str
          - auth_creds: AuthCredentials (valid token to test against)

        Tests to implement:
          1. alg:none attack — forge JWT with no signature
          2. Expired token replay — send expired JWT, check if still accepted
          3. Missing auth — hit protected endpoints with no token
          4. Weak secret brute-force — try common secrets against JWT
        """
        return []

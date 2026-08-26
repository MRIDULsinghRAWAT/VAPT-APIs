"""
Excessive Data Exposure Attack Module

Strategy:
  1. Compare API response fields vs. what the spec says the frontend consumes
  2. Flag endpoints that return significantly more data than documented
  3. Look for sensitive field patterns (password, ssn, token, secret, etc.)
"""

from typing import List

from app.attacks.base import AttackResult, BaseAttackModule


class ExcessiveDataAttackModule(BaseAttackModule):
    """Detect Excessive Data Exposure vulnerabilities."""

    @property
    def name(self) -> str:
        return "Excessive Data Exposure Detector"

    @property
    def category(self) -> str:
        return "ExcessiveDataExposure"

    async def run(self, **kwargs) -> List[AttackResult]:
        """
        TODO (Phase 2): Implement Excessive Data Exposure detection.

        Expected kwargs:
          - endpoints: List[EndpointInfo] (with response_schema)
          - base_url: str
          - auth_creds: AuthCredentials

        Algorithm:
          1. Hit each endpoint with valid auth
          2. Diff response keys against spec's documented response schema
          3. Flag extra fields — especially sensitive patterns
          4. Severity based on what's exposed (PII = high, internal IDs = medium)
        """
        return []

"""
Mass Assignment Attack Module

Strategy:
  1. Find endpoints that accept JSON body (POST/PUT/PATCH)
  2. Inject privileged fields (role, isAdmin, is_staff, verified, etc.)
  3. Check if the server silently accepts and persists these fields
"""

from typing import List

from app.attacks.base import AttackResult, BaseAttackModule

# Common privileged fields to inject
PRIVILEGED_FIELDS = [
    ("role", "admin"),
    ("isAdmin", True),
    ("is_admin", True),
    ("is_staff", True),
    ("admin", True),
    ("verified", True),
    ("is_verified", True),
    ("permissions", ["admin", "write", "delete"]),
    ("user_type", "admin"),
    ("privilege", "elevated"),
    ("account_type", "premium"),
]


class MassAssignmentAttackModule(BaseAttackModule):
    """Detect Mass Assignment vulnerabilities."""

    @property
    def name(self) -> str:
        return "Mass Assignment Fuzzer"

    @property
    def category(self) -> str:
        return "MassAssignment"

    async def run(self, **kwargs) -> List[AttackResult]:
        """
        TODO (Phase 2): Implement Mass Assignment detection.

        Expected kwargs:
          - endpoints: List[EndpointInfo] (POST/PUT/PATCH with request bodies)
          - base_url: str
          - auth_creds: AuthCredentials

        Algorithm:
          1. For each endpoint accepting a JSON body:
             a. Send normal request (baseline)
             b. Send same request + each privileged field from PRIVILEGED_FIELDS
             c. Read back the resource to check if the field was persisted
             d. If persisted → Mass Assignment confirmed
        """
        return []

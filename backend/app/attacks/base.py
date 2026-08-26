"""
Base attack module — defines the interface all attack modules implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackResult:
    """Result of a single attack test against an endpoint."""
    vulnerable: bool
    title: str
    category: str                           # e.g. "BOLA", "BrokenAuth"
    endpoint: str
    method: str
    severity: str = "info"                  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str = ""
    evidence: str = ""                      # raw request/response proof
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAttackModule(ABC):
    """
    Abstract base class for all attack modules.

    Each module:
      1. Receives parsed endpoint info + auth credentials
      2. Generates and fires attack requests
      3. Analyzes responses to confirm vulnerability
      4. Returns a list of AttackResult objects
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable module name."""
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """OWASP API Top 10 category this module tests."""
        ...

    @abstractmethod
    async def run(self, **kwargs) -> List[AttackResult]:
        """
        Execute the attack module against the target.

        Concrete modules define their own kwargs (e.g. endpoints,
        auth, base_url), but all return List[AttackResult].
        """
        ...

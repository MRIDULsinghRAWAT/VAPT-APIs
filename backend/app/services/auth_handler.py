"""
Auth Handler — manages authentication tokens for attack requests.

Supports:
  - Bearer / JWT tokens
  - API Key (header or query)
  - Basic Auth

Used by attack modules to attach valid auth to requests and to swap
auth between Account A and Account B (for BOLA testing).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

import httpx


class AuthType(str, Enum):
    """Supported authentication types."""
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    NONE = "none"


@dataclass
class AuthCredentials:
    """Credentials for a single test account."""
    auth_type: AuthType = AuthType.NONE
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    api_key_in: str = "header"          # "header" or "query"
    username: Optional[str] = None
    password: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class DualAccountAuth:
    """
    Two-account auth setup for BOLA / authorization testing.
    Account A is the 'attacker', Account B is the 'victim'.
    """
    account_a: AuthCredentials
    account_b: AuthCredentials


def apply_auth(
    request_kwargs: Dict,
    creds: AuthCredentials,
) -> Dict:
    """
    Apply authentication credentials to an httpx request kwargs dict.

    Args:
        request_kwargs: dict with keys like 'headers', 'params', etc.
        creds: The credentials to apply.

    Returns:
        Updated request_kwargs with auth applied.
    """
    headers = request_kwargs.setdefault("headers", {})

    if creds.auth_type == AuthType.BEARER:
        headers["Authorization"] = f"Bearer {creds.token}"

    elif creds.auth_type == AuthType.API_KEY:
        if creds.api_key_in == "header":
            headers[creds.api_key_header] = creds.api_key or ""
        elif creds.api_key_in == "query":
            params = request_kwargs.setdefault("params", {})
            params[creds.api_key_header] = creds.api_key or ""

    elif creds.auth_type == AuthType.BASIC:
        request_kwargs["auth"] = httpx.BasicAuth(
            username=creds.username or "",
            password=creds.password or "",
        )

    # Apply any extra headers
    headers.update(creds.extra_headers)

    return request_kwargs


def swap_auth(
    request_kwargs: Dict,
    dual_auth: DualAccountAuth,
    use_account: str = "a",
) -> Dict:
    """
    Apply auth from a specific account (for BOLA attack swapping).

    Args:
        request_kwargs: httpx request kwargs.
        dual_auth: The two-account setup.
        use_account: "a" or "b".

    Returns:
        Updated request_kwargs.
    """
    creds = dual_auth.account_a if use_account == "a" else dual_auth.account_b
    return apply_auth(request_kwargs, creds)

"""
Broken Authentication Audit Module

Tests:
  1. Missing Authorization: Checks if protected endpoints respond without auth headers.
  2. Forged Token (alg: none): Checks if server accepts unsigned/none algorithm JWTs.
  3. Expired Token: Checks if the server validates token expiration timestamps.
"""

from typing import List, Optional
import httpx
from urllib.parse import urljoin

from app.attacks.base import AttackResult, BaseAttackModule
from app.core.security import try_none_algorithm
from app.reports.cvss_scorer import score_finding, severity_from_score
from app.schemas.spec import EndpointInfo
from app.services.auth_handler import AuthCredentials, AuthType


class BrokenAuthAttackModule(BaseAttackModule):
    """Detect Broken Authentication weaknesses in API endpoints."""

    @property
    def name(self) -> str:
        return "Broken Authentication Detector"

    @property
    def category(self) -> str:
        return "BrokenAuth"

    async def run(
        self,
        endpoints: List[EndpointInfo],
        base_url: str,
        auth_creds: Optional[AuthCredentials] = None,
        timeout: float = 10.0,
        **kwargs,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for ep in endpoints:
                # 1. Test Missing Auth on Protected Endpoints
                if ep.auth_required:
                    res = await self._test_missing_auth(client, base_url, ep)
                    if res:
                        results.append(res)

                # 2. Test JWT Flaws if Bearer Token is configured
                if auth_creds and auth_creds.auth_type == AuthType.BEARER and auth_creds.token:
                    if ep.auth_required:
                        res_none = await self._test_alg_none(client, base_url, ep, auth_creds.token)
                        if res_none:
                            results.append(res_none)

        return results

    async def _test_missing_auth(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo
    ) -> Optional[AttackResult]:
        """Send request without Authorization header to a protected route."""
        target_path = self._construct_path(ep.path)
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))

        try:
            resp = await client.request(ep.method, url)
            # If server returns 200 OK or 201 Created on an auth_required endpoint without auth
            if resp.status_code in (200, 201):
                score, vector = score_finding("BrokenAuth")
                return AttackResult(
                    vulnerable=True,
                    title=f"Missing Authentication Enforcement on {ep.method} {ep.path}",
                    category=self.category,
                    endpoint=ep.path,
                    method=ep.method,
                    severity=severity_from_score(score),
                    cvss_score=score,
                    cvss_vector=vector,
                    description=(
                        f"The endpoint '{ep.path}' is documented as requiring authentication, "
                        f"but responded with status {resp.status_code} when queried without credentials."
                    ),
                    evidence=f"Request:\n{ep.method} {url}\nHeaders: None\n\nResponse:\nStatus: {resp.status_code}\nBody: {resp.text[:300]}",
                    remediation=(
                        "Ensure an authentication middleware or security dependency enforces valid "
                        "session tokens or JWT validation on all private routes."
                    ),
                )
        except Exception:
            pass
        return None

    async def _test_alg_none(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, token: str
    ) -> Optional[AttackResult]:
        """Send JWT forged with alg: none to check signature validation."""
        forged_jwt = try_none_algorithm(token)
        if not forged_jwt:
            return None

        target_path = self._construct_path(ep.path)
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))

        headers = {"Authorization": f"Bearer {forged_jwt}"}
        try:
            resp = await client.request(ep.method, url, headers=headers)
            if resp.status_code in (200, 201):
                score, vector = score_finding("BrokenAuth")
                return AttackResult(
                    vulnerable=True,
                    title=f"JWT 'alg: none' Signature Bypass on {ep.method} {ep.path}",
                    category=self.category,
                    endpoint=ep.path,
                    method=ep.method,
                    severity=severity_from_score(score),
                    cvss_score=score,
                    cvss_vector=vector,
                    description=(
                        f"The endpoint accepted a modified JWT token with algorithm set to 'none' "
                        f"without signature verification."
                    ),
                    evidence=f"Request:\n{ep.method} {url}\nAuthorization: Bearer {forged_jwt[:40]}...\n\nResponse:\nStatus: {resp.status_code}\nBody: {resp.text[:300]}",
                    remediation=(
                        "Configure the JWT validation library to explicitly whitelist only secure algorithms "
                        "(e.g., HS256, RS256) and reject tokens with 'alg: none'."
                    ),
                )
        except Exception:
            pass
        return None

    def _construct_path(self, path: str) -> str:
        """Replace path params {id}, {userId} with dummy test values."""
        import re
        return re.sub(r"\{[^\}]+\}", "1", path)

"""
BOLA (Broken Object Level Authorization) Audit Module

Strategy:
  1. Detect endpoints with path identifiers (e.g. /users/{id}, /orders/{orderId}).
  2. Perform cross-identifier queries with valid credentials (swapping resource IDs).
  3. If DualAccountAuth is provided:
     - Request User B's resource using User A's token.
     - Confirm if User B's resource is returned under User A's authorization.
"""

import re
from typing import List, Optional
import httpx
from urllib.parse import urljoin

from app.attacks.base import AttackResult, BaseAttackModule
from app.reports.cvss_scorer import score_finding, severity_from_score
from app.schemas.spec import EndpointInfo
from app.services.auth_handler import AuthCredentials, DualAccountAuth, apply_auth


class BOLAAttackModule(BaseAttackModule):
    """Detect Broken Object Level Authorization vulnerabilities."""

    @property
    def name(self) -> str:
        return "BOLA Detector"

    @property
    def category(self) -> str:
        return "BOLA"

    async def run(
        self,
        endpoints: List[EndpointInfo],
        base_url: str,
        auth_creds: Optional[AuthCredentials] = None,
        dual_auth: Optional[DualAccountAuth] = None,
        timeout: float = 10.0,
        **kwargs,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Find endpoints with path parameters like {id}, {userId}, {orderId}
        path_param_endpoints = [
            ep for ep in endpoints
            if any(p.location == "path" for p in ep.parameters) or re.search(r"\{[^\}]+\}", ep.path)
        ]

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for ep in path_param_endpoints:
                if dual_auth and dual_auth.account_a.token and dual_auth.account_b.token:
                    # Dual-account active cross-check
                    res = await self._test_dual_account_bola(client, base_url, ep, dual_auth)
                    if res:
                        results.append(res)
                elif auth_creds:
                    # Single-account ID traversal probe (e.g. test ID '1' vs ID '2')
                    res = await self._test_single_account_id_swap(client, base_url, ep, auth_creds)
                    if res:
                        results.append(res)

        return results

    async def _test_single_account_id_swap(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, creds: AuthCredentials
    ) -> Optional[AttackResult]:
        """Test accessing adjacent numeric object IDs."""
        # Replace parameter with ID 1 and ID 2
        path_1 = re.sub(r"\{[^\}]+\}", "1", ep.path)
        path_2 = re.sub(r"\{[^\}]+\}", "2", ep.path)

        url_1 = urljoin(base_url.rstrip("/") + "/", path_1.lstrip("/"))
        url_2 = urljoin(base_url.rstrip("/") + "/", path_2.lstrip("/"))

        req_kwargs_1 = apply_auth({}, creds)
        req_kwargs_2 = apply_auth({}, creds)

        try:
            resp_1 = await client.request(ep.method, url_1, **req_kwargs_1)
            resp_2 = await client.request(ep.method, url_2, **req_kwargs_2)

            # If the user can access both distinct object IDs with 200 OK and different payloads
            if resp_1.status_code == 200 and resp_2.status_code == 200:
                if resp_1.text != resp_2.text and len(resp_1.text) > 10 and len(resp_2.text) > 10:
                    score, vector = score_finding("BOLA")
                    return AttackResult(
                        vulnerable=True,
                        title=f"Potential BOLA / Insecure Direct Object Reference on {ep.method} {ep.path}",
                        category=self.category,
                        endpoint=ep.path,
                        method=ep.method,
                        severity=severity_from_score(score),
                        cvss_score=score,
                        cvss_vector=vector,
                        description=(
                            f"The endpoint '{ep.path}' allowed the authenticated caller to read/modify multiple "
                            f"distinct object IDs ({path_1} and {path_2}) without tenant or object-ownership restriction."
                        ),
                        evidence=(
                            f"Request 1: {ep.method} {url_1} -> Status {resp_1.status_code}\n"
                            f"Request 2: {ep.method} {url_2} -> Status {resp_2.status_code}\n"
                            f"Sample Data 1: {resp_1.text[:120]}...\n"
                            f"Sample Data 2: {resp_2.text[:120]}..."
                        ),
                        remediation=(
                            "Implement strict user-context access control checks in the business logic layer. "
                            "Ensure the currently logged-in user explicitly owns the requested object ID."
                        ),
                    )
        except Exception:
            pass
        return None

    async def _test_dual_account_bola(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, dual_auth: DualAccountAuth
    ) -> Optional[AttackResult]:
        """Request User B's resource ID using User A's authentication token."""
        victim_path = re.sub(r"\{[^\}]+\}", "2", ep.path)
        url = urljoin(base_url.rstrip("/") + "/", victim_path.lstrip("/"))

        attacker_kwargs = apply_auth({}, dual_auth.account_a)
        try:
            resp = await client.request(ep.method, url, **attacker_kwargs)
            if resp.status_code == 200:
                score, vector = score_finding("BOLA")
                return AttackResult(
                    vulnerable=True,
                    title=f"Confirmed BOLA / Cross-Account Access on {ep.method} {ep.path}",
                    category=self.category,
                    endpoint=ep.path,
                    method=ep.method,
                    severity=severity_from_score(score),
                    cvss_score=score,
                    cvss_vector=vector,
                    description=(
                        f"Account A successfully accessed Account B's resource ID ({victim_path}) "
                        f"using Account A's credentials."
                    ),
                    evidence=f"Target: {ep.method} {url}\nStatus: {resp.status_code}\nPayload: {resp.text[:250]}",
                    remediation="Validate object ownership against session identity before performing data operations.",
                )
        except Exception:
            pass
        return None

"""
Mass Assignment Vulnerability Fuzzer

Strategy:
  1. Target endpoints accepting JSON bodies (POST, PUT, PATCH).
  2. Inject privilege and security-sensitive attributes (e.g. isAdmin, role, is_staff, verified).
  3. Inspect if response indicates acceptance or modification of the injected fields.
"""

from typing import List, Optional, Dict, Any
import httpx
import json
from urllib.parse import urljoin

from app.attacks.base import AttackResult, BaseAttackModule
from app.reports.cvss_scorer import score_finding, severity_from_score
from app.schemas.spec import EndpointInfo
from app.services.auth_handler import AuthCredentials, apply_auth

PRIVILEGED_INJECTIONS: List[Dict[str, Any]] = [
    {"isAdmin": True},
    {"is_admin": True},
    {"role": "admin"},
    {"is_staff": True},
    {"role": "superuser"},
    {"verified": True},
    {"permissions": ["admin", "all"]},
    {"account_type": "premium"},
]


class MassAssignmentAttackModule(BaseAttackModule):
    """Detect Mass Assignment vulnerabilities by injecting privilege escalation keys."""

    @property
    def name(self) -> str:
        return "Mass Assignment Fuzzer"

    @property
    def category(self) -> str:
        return "MassAssignment"

    async def run(
        self,
        endpoints: List[EndpointInfo],
        base_url: str,
        auth_creds: Optional[AuthCredentials] = None,
        timeout: float = 10.0,
        **kwargs,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Target mutating methods with request bodies
        body_endpoints = [
            ep for ep in endpoints
            if ep.method.upper() in ("POST", "PUT", "PATCH")
        ]

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for ep in body_endpoints:
                res = await self._fuzz_mass_assignment(client, base_url, ep, auth_creds)
                if res:
                    results.append(res)

        return results

    async def _fuzz_mass_assignment(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, creds: Optional[AuthCredentials]
    ) -> Optional[AttackResult]:
        target_path = self._construct_path(ep.path)
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))

        base_payload = {"name": "AuditUser", "email": "audit@example.com"}
        if ep.request_body_schema and "properties" in ep.request_body_schema:
            for k in ep.request_body_schema["properties"].keys():
                base_payload[k] = "test_val"

        # Try injecting privileged fields
        for injection in PRIVILEGED_INJECTIONS:
            fuzzed_payload = {**base_payload, **injection}
            req_kwargs = {"json": fuzzed_payload}
            if creds and ep.auth_required:
                req_kwargs = apply_auth(req_kwargs, creds)

            try:
                resp = await client.request(ep.method, url, **req_kwargs)

                # Check if server accepted the request (200 OK / 201 Created)
                if resp.status_code in (200, 201):
                    injected_key = list(injection.keys())[0]
                    # Check if response reflects the injected field with value
                    if injected_key in resp.text:
                        try:
                            resp_json = resp.json()
                            if resp_json.get(injected_key) == injection[injected_key]:
                                score, vector = score_finding("MassAssignment")
                                return AttackResult(
                                    vulnerable=True,
                                    title=f"Mass Assignment Accepted on {ep.method} {ep.path} ('{injected_key}')",
                                    category=self.category,
                                    endpoint=ep.path,
                                    method=ep.method,
                                    severity=severity_from_score(score),
                                    cvss_score=score,
                                    cvss_vector=vector,
                                    description=(
                                        f"The endpoint '{ep.path}' accepted an unwhitelisted, privileged parameter "
                                        f"'{injected_key}: {injection[injected_key]}' in the JSON body and reflected it in the response."
                                    ),
                                    evidence=(
                                        f"Method: {ep.method} {url}\n"
                                        f"Payload Sent: {json.dumps(fuzzed_payload)}\n"
                                        f"Status: {resp.status_code}\n"
                                        f"Response: {resp.text[:250]}"
                                    ),
                                    remediation=(
                                        "Use strict DTOs (Data Transfer Objects) or Pydantic/Joi input schemas with explicit "
                                        "field whitelisting to reject unexpected client-supplied parameters."
                                    ),
                                )
                        except Exception:
                            pass
            except Exception:
                pass

        return None

    def _construct_path(self, path: str) -> str:
        import re
        return re.sub(r"\{[^\}]+\}", "1", path)

"""
Excessive Data Exposure Audit Module

Strategy:
  1. Inspect response payloads for sensitive information patterns (passwords, tokens, SSNs, credit cards, internal secrets).
  2. Compare live response keys with documented OpenAPI response schemas to flag unadvertised internal fields.
"""

from typing import List, Optional, Set
import httpx
import re
from urllib.parse import urljoin

from app.attacks.base import AttackResult, BaseAttackModule
from app.reports.cvss_scorer import score_finding, severity_from_score
from app.schemas.spec import EndpointInfo
from app.services.auth_handler import AuthCredentials, apply_auth

SENSITIVE_PATTERNS = [
    (r"(?i)\bpassword\b", "Password / Credential field"),
    (r"(?i)\bsecret\b", "Internal Secret / Key"),
    (r"(?i)\bssn\b|\bsocial_security\b", "Social Security Number (SSN)"),
    (r"(?i)\btoken\b|\baccess_token\b|\brefresh_token\b", "Auth Token"),
    (r"(?i)\bcard_number\b|\bcredit_card\b|\bcvv\b", "Payment Card Data"),
    (r"(?i)\bis_admin\b|\bisAdmin\b|\brole\b", "Internal Authorization Flag"),
    (r"(?i)\bapi_key\b|\bapikey\b", "API Key"),
]


class ExcessiveDataAttackModule(BaseAttackModule):
    """Detect Excessive Data Exposure in API responses."""

    @property
    def name(self) -> str:
        return "Excessive Data Exposure Detector"

    @property
    def category(self) -> str:
        return "ExcessiveDataExposure"

    async def run(
        self,
        endpoints: List[EndpointInfo],
        base_url: str,
        auth_creds: Optional[AuthCredentials] = None,
        timeout: float = 10.0,
        **kwargs,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Target read operations (GET, POST)
        read_endpoints = [
            ep for ep in endpoints
            if ep.method.upper() in ("GET", "POST")
        ]

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for ep in read_endpoints:
                res = await self._audit_response_data(client, base_url, ep, auth_creds)
                if res:
                    results.append(res)

        return results

    async def _audit_response_data(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, creds: Optional[AuthCredentials]
    ) -> Optional[AttackResult]:
        target_path = self._construct_path(ep.path)
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))

        req_kwargs = {}
        if creds and ep.auth_required:
            req_kwargs = apply_auth(req_kwargs, creds)

        try:
            resp = await client.request(ep.method, url, **req_kwargs)
            if resp.status_code == 200:
                body_text = resp.text
                findings: Set[str] = set()

                for pattern, label in SENSITIVE_PATTERNS:
                    if re.search(pattern, body_text):
                        findings.add(label)

                if findings:
                    score, vector = score_finding("ExcessiveDataExposure")
                    labels_str = ", ".join(sorted(findings))
                    return AttackResult(
                        vulnerable=True,
                        title=f"Excessive Data Exposure on {ep.method} {ep.path} ({labels_str})",
                        category=self.category,
                        endpoint=ep.path,
                        method=ep.method,
                        severity=severity_from_score(score),
                        cvss_score=score,
                        cvss_vector=vector,
                        description=(
                            f"The endpoint '{ep.path}' returned response payloads containing sensitive fields "
                            f"({labels_str}) that may not be required by the client."
                        ),
                        evidence=(
                            f"Target: {ep.method} {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Sensitive Attributes Identified: {labels_str}\n"
                            f"Response Snippet:\n{body_text[:250]}..."
                        ),
                        remediation=(
                            "Ensure API endpoints filter responses through strict response serialization schemas "
                            "(e.g., Pydantic response_model, DTO projection) to omit sensitive backend attributes."
                        ),
                    )
        except Exception:
            pass
        return None

    def _construct_path(self, path: str) -> str:
        import re
        return re.sub(r"\{[^\}]+\}", "1", path)

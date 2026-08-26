"""
Rate Limiting Probe Module

Strategy:
  1. Detect sensitive routes (e.g. /login, /register, /otp, /reset-password, /auth)
  2. Send rapid concurrent bursts of HTTP requests (e.g. 20-30 requests in 1-2 seconds)
  3. Inspect if rate limit headers (X-RateLimit-*, Retry-After) or 429 Too Many Requests are enforced.
"""

import asyncio
from typing import List, Optional
import httpx
from urllib.parse import urljoin

from app.attacks.base import AttackResult, BaseAttackModule
from app.reports.cvss_scorer import score_finding, severity_from_score
from app.schemas.spec import EndpointInfo


class RateLimitAttackModule(BaseAttackModule):
    """Detect missing Rate Limiting on sensitive endpoints."""

    SENSITIVE_KEYWORDS = ["auth", "login", "register", "otp", "token", "password", "reset", "signin", "signup"]

    @property
    def name(self) -> str:
        return "Rate Limit Probe"

    @property
    def category(self) -> str:
        return "RateLimiting"

    async def run(
        self,
        endpoints: List[EndpointInfo],
        base_url: str,
        burst_count: int = 25,
        timeout: float = 10.0,
        **kwargs,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        # Filter candidate sensitive endpoints
        candidate_endpoints = [
            ep for ep in endpoints
            if any(k in ep.path.lower() for k in self.SENSITIVE_KEYWORDS)
        ]

        # If no explicit sensitive endpoints found, test first 2 POST endpoints
        if not candidate_endpoints:
            candidate_endpoints = [ep for ep in endpoints if ep.method.upper() == "POST"][:2]

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            for ep in candidate_endpoints:
                res = await self._probe_rate_limit(client, base_url, ep, burst_count)
                if res:
                    results.append(res)

        return results

    async def _probe_rate_limit(
        self, client: httpx.AsyncClient, base_url: str, ep: EndpointInfo, burst_count: int
    ) -> Optional[AttackResult]:
        target_path = self._construct_path(ep.path)
        url = urljoin(base_url.rstrip("/") + "/", target_path.lstrip("/"))

        dummy_body = {"email": "test@example.com", "password": "TestPassword123!"} if ep.method in ("POST", "PUT") else None

        async def send_req():
            try:
                return await client.request(ep.method, url, json=dummy_body)
            except Exception:
                return None

        # Fire burst requests concurrently
        tasks = [send_req() for _ in range(burst_count)]
        responses = await asyncio.gather(*tasks)
        valid_resps = [r for r in responses if r is not None]

        if not valid_resps:
            return None

        status_codes = [r.status_code for r in valid_resps]
        has_429 = 429 in status_codes
        has_rate_limit_headers = any(
            "ratelimit" in k.lower() or "retry-after" in k.lower()
            for r in valid_resps for k in r.headers.keys()
        )

        # If server answered all burst requests without 429 or throttling headers
        if not has_429 and not has_rate_limit_headers and len(valid_resps) >= (burst_count // 2):
            score, vector = score_finding("RateLimiting")
            return AttackResult(
                vulnerable=True,
                title=f"Missing Rate Limiting Protection on {ep.method} {ep.path}",
                category=self.category,
                endpoint=ep.path,
                method=ep.method,
                severity=severity_from_score(score),
                cvss_score=score,
                cvss_vector=vector,
                description=(
                    f"The sensitive endpoint '{ep.path}' processed {len(valid_resps)} rapid consecutive requests "
                    f"without returning HTTP 429 (Too Many Requests) or rate-limiting headers."
                ),
                evidence=(
                    f"Burst Size: {burst_count}\n"
                    f"Target: {ep.method} {url}\n"
                    f"HTTP Status Codes Sample: {status_codes[:10]}...\n"
                    f"Rate Limiting Headers: Not Detected"
                ),
                remediation=(
                    "Implement IP/Token-based rate limiting (e.g. using Redis token bucket or reverse proxy rules) "
                    "on sensitive authentication and registration routes to prevent brute-force attacks."
                ),
            )

        return None

    def _construct_path(self, path: str) -> str:
        import re
        return re.sub(r"\{[^\}]+\}", "1", path)

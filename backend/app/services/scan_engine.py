"""
Scan Engine Orchestrator

Coordinates and executes attack modules against parsed API specs.
Populates findings and updates scan status in the database.
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.attacks.base import AttackResult
from app.attacks.broken_auth import BrokenAuthAttackModule
from app.attacks.rate_limit import RateLimitAttackModule
from app.attacks.bola import BOLAAttackModule
from app.attacks.mass_assignment import MassAssignmentAttackModule
from app.attacks.excessive_data import ExcessiveDataAttackModule
from app.db.models import Scan, Finding, ScanStatus, Severity
from app.schemas.spec import ParsedSpec
from app.services.auth_handler import AuthCredentials, DualAccountAuth


class ScanEngine:
    """Orchestrates comprehensive VAPT assessment across enabled modules."""

    def __init__(self):
        self.modules = [
            BrokenAuthAttackModule(),
            RateLimitAttackModule(),
            BOLAAttackModule(),
            MassAssignmentAttackModule(),
            ExcessiveDataAttackModule(),
        ]

    async def execute_scan(
        self,
        db: AsyncSession,
        scan_id: int,
        parsed_spec: ParsedSpec,
        base_url: str,
        auth_creds: Optional[AuthCredentials] = None,
        dual_auth: Optional[DualAccountAuth] = None,
    ) -> List[Finding]:
        # Retrieve scan record
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return []

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.total_endpoints = len(parsed_spec.endpoints)
        await db.commit()

        all_findings: List[Finding] = []

        try:
            for module in self.modules:
                module_results: List[AttackResult] = await module.run(
                    endpoints=parsed_spec.endpoints,
                    base_url=base_url,
                    auth_creds=auth_creds,
                    dual_auth=dual_auth,
                )

                for res in module_results:
                    if res.vulnerable:
                        finding = Finding(
                            scan_id=scan.id,
                            title=res.title,
                            category=res.category,
                            severity=Severity(res.severity.lower()),
                            cvss_score=res.cvss_score,
                            cvss_vector=res.cvss_vector,
                            endpoint=res.endpoint,
                            method=res.method,
                            description=res.description,
                            evidence=res.evidence,
                            remediation=res.remediation,
                        )
                        db.add(finding)
                        all_findings.append(finding)

            scan.status = ScanStatus.COMPLETED
            scan.total_findings = len(all_findings)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

        except Exception as e:
            scan.status = ScanStatus.FAILED
            await db.commit()
            raise e

        return all_findings

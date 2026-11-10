"""
AI Assistant endpoints — remediation generation and security chat.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.ai_service import generate_remediation, chat

router = APIRouter()


# ── Request / Response Schemas ─────────────────────────────────────────────


class FindingInput(BaseModel):
    """A vulnerability finding to analyze."""
    title: str
    category: str
    severity: str
    cvss_score: Optional[float] = None
    endpoint: str = ""
    method: str = "GET"
    description: str = ""
    evidence: str = ""


class RemediationRequest(BaseModel):
    """Request body for AI remediation."""
    finding: FindingInput


class RemediationResponse(BaseModel):
    """AI-generated remediation advice."""
    explanation: str
    fix_code: str
    owasp_reference: str
    cwe_id: str
    risk_analysis: str


class ChatMessage(BaseModel):
    role: str = "user"
    content: str = ""


class ChatRequest(BaseModel):
    """Request body for security chat."""
    message: str
    scan_context: Optional[Dict[str, Any]] = None
    chat_history: Optional[List[ChatMessage]] = None


class ChatResponse(BaseModel):
    """AI chat response."""
    response: str


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.post("/remediate", response_model=RemediationResponse)
def ai_remediate(req: RemediationRequest):
    """
    Generate AI-powered remediation for a vulnerability finding.

    Sends the finding to Gemini and returns:
    - Plain-English explanation of the vulnerability
    - Copy-paste fix code (Python/FastAPI)
    - OWASP API Top 10 reference
    - CWE identifier
    - Risk analysis
    """
    finding_dict = req.finding.model_dump()
    result = generate_remediation(finding_dict)
    return RemediationResponse(**result)


@router.post("/chat", response_model=ChatResponse)
def ai_chat(req: ChatRequest):
    """
    Natural-language security chat — ask questions about scan results,
    request bug bounty reports, or get general API security advice.
    """
    history = None
    if req.chat_history:
        history = [m.model_dump() for m in req.chat_history]

    response_text = chat(
        message=req.message,
        scan_context=req.scan_context,
        chat_history=history,
    )
    return ChatResponse(response=response_text)


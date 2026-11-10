"""
AI Service — Gemini LLM integration for vulnerability remediation and security chat.

Uses Google Gemini API to:
  1. Generate contextual remediation for scan findings
  2. Power a natural-language security chat grounded in scan results
"""

import json
from typing import Any, Dict, List, Optional

import google.generativeai as genai

from app.core.config import settings


def _get_model():
    """Configure and return the Gemini model."""
    key = (settings.GEMINI_API_KEY or "").strip()
    if not key or "your-gemini" in key:
        raise ValueError("GEMINI_API_KEY is not configured in .env file.")
    genai.configure(api_key=key)
    return genai.GenerativeModel("gemini-2.0-flash")


# ── 1. AI-Powered Remediation ──────────────────────────────────────────────


REMEDIATION_SYSTEM_PROMPT = """You are an expert application security engineer specializing in API security and the OWASP API Security Top 10 (2023).

You will receive a vulnerability finding from an automated VAPT scan. Your job is to provide:

1. **explanation** — A clear, plain-English explanation of the vulnerability: what it is, why it's dangerous, and how a real attacker would exploit it. Write 3-5 sentences.

2. **fix_code** — A concrete, copy-paste-ready code fix in Python (FastAPI) that remediates this specific vulnerability. Use proper middleware, decorators, or validation patterns. Include comments.

3. **owasp_reference** — The relevant OWASP API Security Top 10 (2023) category ID and name (e.g., "API1:2023 - Broken Object Level Authorization") with a one-line summary.

4. **cwe_id** — The most relevant CWE identifier (e.g., "CWE-639: Authorization Bypass Through User-Controlled Key").

5. **risk_analysis** — A brief risk assessment: what data/systems are at stake, potential business impact, and urgency of fix (1-3 sentences).

Respond ONLY with valid JSON matching this exact schema:
{
  "explanation": "...",
  "fix_code": "...",
  "owasp_reference": "...",
  "cwe_id": "...",
  "risk_analysis": "..."
}

Do not include markdown fences or any text outside the JSON object."""


def generate_remediation(finding: Dict[str, Any], model: Optional[Any] = None) -> Dict[str, str]:
    """
    Generate AI-powered remediation advice for a single vulnerability finding.

    Args:
        finding: Dict with keys: title, category, severity, cvss_score,
                 endpoint, method, description, evidence
        model: Optional injected model instance (for testing)

    Returns:
        Dict with keys: explanation, fix_code, owasp_reference, cwe_id, risk_analysis
    """
    try:
        active_model = model or _get_model()

        finding_text = (
            f"Title: {finding.get('title', 'N/A')}\n"
            f"Category: {finding.get('category', 'N/A')}\n"
            f"Severity: {finding.get('severity', 'N/A')}\n"
            f"CVSS Score: {finding.get('cvss_score', 'N/A')}\n"
            f"Endpoint: {finding.get('method', 'GET')} {finding.get('endpoint', 'N/A')}\n"
            f"Description: {finding.get('description', 'N/A')}\n"
            f"Evidence (PoC):\n{finding.get('evidence', 'No evidence provided')}\n"
        )

        prompt = f"{REMEDIATION_SYSTEM_PROMPT}\n\n--- VULNERABILITY FINDING ---\n{finding_text}"

        response = active_model.generate_content(prompt)
        text = response.text.strip()

        # Strip markdown fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        if text.startswith("json"):
            text = text[4:].strip()

        result = json.loads(text)

        # Ensure all expected keys exist
        for key in ("explanation", "fix_code", "owasp_reference", "cwe_id", "risk_analysis"):
            result.setdefault(key, "Not available.")

        return result

    except json.JSONDecodeError:
        # If the LLM didn't return valid JSON, wrap raw text
        return {
            "explanation": response.text if 'response' in dir() else "AI analysis unavailable.",
            "fix_code": "# Unable to generate structured code fix. Please review the explanation above.",
            "owasp_reference": "See https://owasp.org/API-Security/",
            "cwe_id": "N/A",
            "risk_analysis": "Please review the finding details for risk assessment.",
        }
    except Exception as e:
        return {
            "explanation": f"AI service encountered an error: {str(e)}",
            "fix_code": "# AI service unavailable. Please check your GEMINI_API_KEY in .env",
            "owasp_reference": "See https://owasp.org/API-Security/",
            "cwe_id": "N/A",
            "risk_analysis": "Unable to generate risk analysis at this time.",
        }


# ── 2. Natural Language Security Chat ──────────────────────────────────────


CHAT_SYSTEM_PROMPT = """You are a senior penetration tester and API security consultant embedded in an automated VAPT (Vulnerability Assessment & Penetration Testing) tool.

You help security engineers understand scan results, write reports, and plan remediation.

GUIDELINES:
- Ground your answers in the scan data provided (if any).
- Be specific — reference endpoint paths, CVSS scores, and finding titles from the scan context.
- When asked to explain a finding, describe HOW the attack works step-by-step.
- When asked for a bug bounty report, use standard format: Title, Severity, Description, Steps to Reproduce, Impact, Remediation.
- When no scan data is available, provide general API security guidance based on OWASP API Security Top 10 (2023).
- Keep responses concise but thorough.
- Use markdown formatting for readability."""


def chat(
    message: str,
    scan_context: Optional[Dict[str, Any]] = None,
    chat_history: Optional[List[Dict[str, str]]] = None,
    model: Optional[Any] = None,
) -> str:
    """
    Natural-language security chat powered by Gemini.

    Args:
        message: User's question or request
        scan_context: Optional dict with scan results (findings list, target info)
        chat_history: Optional list of previous messages [{"role": "user"|"assistant", "content": "..."}]
        model: Optional injected model instance (for testing)

    Returns:
        AI response as a string (markdown formatted)
    """
    try:
        active_model = model or _get_model()

        # Build context block
        context_block = ""
        if scan_context:
            findings = scan_context.get("findings", [])
            if findings:
                context_block = "\n--- CURRENT SCAN RESULTS ---\n"
                context_block += f"Target: {scan_context.get('target_url', 'Unknown')}\n"
                context_block += f"Total Findings: {len(findings)}\n\n"
                for i, f in enumerate(findings, 1):
                    context_block += (
                        f"Finding #{i}:\n"
                        f"  Title: {f.get('title', 'N/A')}\n"
                        f"  Category: {f.get('category', 'N/A')}\n"
                        f"  Severity: {f.get('severity', 'N/A')}\n"
                        f"  CVSS: {f.get('cvss_score', 'N/A')}\n"
                        f"  Endpoint: {f.get('method', 'GET')} {f.get('endpoint', 'N/A')}\n"
                        f"  Description: {f.get('description', 'N/A')}\n\n"
                    )

        # Build conversation history
        history_block = ""
        if chat_history:
            history_block = "\n--- CONVERSATION HISTORY ---\n"
            for msg in chat_history[-10:]:  # Last 10 messages for context window
                role = msg.get("role", "user").upper()
                history_block += f"{role}: {msg.get('content', '')}\n"
            history_block += "--- END HISTORY ---\n"

        prompt = (
            f"{CHAT_SYSTEM_PROMPT}\n"
            f"{context_block}"
            f"{history_block}"
            f"\nUSER QUESTION: {message}"
        )

        response = active_model.generate_content(prompt)
        return response.text.strip()

    except Exception as e:
        return (
            f"⚠️ **AI Assistant Error**\n\n"
            f"Unable to process your request: {str(e)}\n\n"
            f"Please verify your `GEMINI_API_KEY` is set correctly in the backend `.env` file."
        )


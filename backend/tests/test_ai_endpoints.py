"""
Unit tests for AI Assistant service (remediation generation and security chat).
"""

from unittest.mock import MagicMock

from app.services.ai_service import generate_remediation, chat


def test_generate_remediation_mocked():
    """Test generate_remediation returns parsed structured advice."""
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = '''{
        "explanation": "Broken Object Level Authorization occurs when user IDs are manipulated without verification.",
        "fix_code": "@app.get('/users/{user_id}')\\ndef get_user(user_id: int): pass",
        "owasp_reference": "API1:2023 - Broken Object Level Authorization",
        "cwe_id": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "risk_analysis": "Critical data exposure risk across multiple tenants."
    }'''
    mock_model.generate_content.return_value = mock_response

    finding = {
        "title": "BOLA / IDOR on GET /users/{id}",
        "category": "BOLA",
        "severity": "critical",
        "cvss_score": 8.5,
        "endpoint": "/users/2",
        "method": "GET",
        "description": "User 1 accessed User 2 data",
        "evidence": "HTTP 200 OK with SSN leak"
    }
    res = generate_remediation(finding, model=mock_model)
    assert "Broken Object Level Authorization" in res["explanation"]
    assert "API1:2023" in res["owasp_reference"]
    assert "CWE-639" in res["cwe_id"]
    assert "def get_user" in res["fix_code"]


def test_chat_mocked():
    """Test chat returns contextual responses."""
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "The highest risk endpoint is GET /users/{id} due to BOLA."
    mock_model.generate_content.return_value = mock_response

    scan_context = {
        "target_url": "http://localhost:8888",
        "findings": [
            {
                "title": "BOLA on /users/{id}",
                "severity": "critical",
                "cvss_score": 9.1,
                "endpoint": "/users/1",
                "method": "GET"
            }
        ]
    }
    res = chat("Which endpoint is the most critical?", scan_context=scan_context, model=mock_model)
    assert "highest risk endpoint" in res

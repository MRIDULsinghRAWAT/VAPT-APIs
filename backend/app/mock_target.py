"""
Live Vulnerable Target API Server (Self-Hosted Mock Target)

This server runs a REAL, LIVE vulnerable REST API locally on port 8888.
Contains genuine, exploitable vulnerabilities for testing:
  - BOLA on /api/v2/users/{id}
  - Missing Auth on /api/v2/admin/audit-logs
  - Missing Rate Limiting on /api/v2/auth/login and /api/v2/auth/verify-otp
  - Mass Assignment on PUT /api/v2/users/{id}
  - Excessive Data Exposure (returns SSN, password_hash, credit_card)
"""

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(
    title="ShopVulnerable Live Target API",
    version="2.4.0",
    description="Live vulnerable target for VAPT penetration testing."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-Memory Vulnerable Database ──
USERS_DB = {
    1: {
        "id": 1,
        "full_name": "Alice Administrator",
        "email": "alice.admin@target.local",
        "role": "admin",
        "ssn": "987-65-4321",
        "credit_card": "4111-2222-3333-4444",
        "password_hash": "$2b$12$e8uq4L9rI...secretHashAlice",
        "is_admin": True,
        "balance": 150000.0,
    },
    2: {
        "id": 2,
        "full_name": "Bob Victim",
        "email": "bob.victim@target.local",
        "role": "customer",
        "ssn": "123-45-6789",
        "credit_card": "5500-0000-1111-2222",
        "password_hash": "$2b$12$K89zQ1v...secretHashBob",
        "is_admin": False,
        "balance": 250.0,
    }
}

AUDIT_LOGS = [
    {"timestamp": "2026-08-27T00:01:00Z", "event": "DATABASE_BACKUP_EXPORT", "user": "alice.admin"},
    {"timestamp": "2026-08-27T00:02:15Z", "event": "API_KEY_ROTATION", "key": "sk_live_99812498124"},
    {"timestamp": "2026-08-27T00:03:00Z", "event": "PAYMENT_GATEWAY_SYNC", "status": "SUCCESS"}
]


# ── Schemas ──
class LoginRequest(BaseModel):
    email: str
    password: str

class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_admin: Optional[bool] = None
    balance: Optional[float] = None


# ── 1. Authentication (Vulnerable to No Rate Limiting) ──
@app.post("/api/v2/auth/login")
async def login(req: LoginRequest):
    # Vulnerability: No rate limiting, returns token immediately
    return {
        "status": "success",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwibmFtZSI6IkJvYiBWaWN0aW0iLCJyb2xlIjoiY3VzdG9tZXIifQ.mockSignature",
        "user_id": 2,
    }

@app.post("/api/v2/auth/verify-otp")
async def verify_otp(phone: str = "test", otp_code: str = "1234"):
    # Vulnerability: No rate limiting on 4-digit OTP
    if otp_code == "1234":
        return {"status": "success", "message": "OTP verified successfully"}
    return {"status": "failed", "message": "Invalid OTP code"}


# ── 2. User Profile (Vulnerable to BOLA + Excessive Data Exposure) ──
@app.get("/api/v2/users/{user_id}/profile")
async def get_user_profile(user_id: int, authorization: Optional[str] = Header(None)):
    # Vulnerability: Returns full internal DB object (including SSN, password_hash, credit_card)
    # BOLA: Does not verify if authorization token matches user_id!
    if user_id not in USERS_DB:
        raise HTTPException(status_code=404, detail="User not found")
    return USERS_DB[user_id]


# ── 3. Profile Update (Vulnerable to Mass Assignment) ──
@app.put("/api/v2/users/{user_id}/profile")
async def update_user_profile(user_id: int, req: Request, authorization: Optional[str] = Header(None)):
    if user_id not in USERS_DB:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Vulnerability: Mass Assignment — accepts all client fields directly!
    body = await req.json()
    user = USERS_DB[user_id]
    for k, v in body.items():
        user[k] = v
    
    return {
        "status": "updated",
        "message": f"User {user_id} profile updated successfully",
        "user": user
    }


# ── 4. Admin Audit Logs (Vulnerable to Broken Auth / Unauthenticated Access) ──
@app.get("/api/v2/admin/system/audit-logs")
async def get_audit_logs():
    # Vulnerability: No auth check at all!
    return {
        "status": "success",
        "count": len(AUDIT_LOGS),
        "audit_logs": AUDIT_LOGS
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8888)

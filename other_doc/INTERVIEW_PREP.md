# Automated VAPT for Web APIs — Master Technical Interview Preparation Guide

This guide is structured to help you excel in **Application Security (AppSec)**, **Cybersecurity**, **Penetration Testing**, and **Backend/DevSecOps** technical interviews. It covers the core project pitch, problem statement, solution design, result generation mechanics, vulnerability deep-dives, code-level examples, database architecture, and potential interview questions.

---

## 1. The Definitive Interview Pitch (Say This in Your Introduction)

### 30-Second Quick Pitch (For General Introductions)
> "I built an Automated Vulnerability Assessment and Penetration Testing (VAPT) Framework specifically engineered for modern REST APIs. Traditional web security scanners rely on crawling HTML web pages and miss API-level business logic flaws. My tool ingests machine-readable OpenAPI and Swagger specifications, automatically maps the full attack surface, and fires concurrent network exploits across the OWASP API Security Top 10—including BOLA, Broken Auth, Mass Assignment, Rate Limiting, and PII leaks. It correlates isolated findings into multi-stage exploit chains, calculates standardized CVSS v3.1 base scores, renders interactive SVG attack topologies, and exports client-ready penetration testing reports with full HTTP request/response proof-of-concept evidence."

---

### 2-Minute Comprehensive Pitch (When Asked: "Walk Me Through Your Major Project")
> "In modern cloud and microservice architectures, the primary attack surface has shifted from traditional HTML frontends to the API layer. However, most developers and small security teams still test APIs manually using Burp Suite or run legacy scanners that don't understand JSON schemas or token-based authorization models.
> 
> To solve this, I designed an automated, spec-aware VAPT engine with four core layers:
> 1. **Recon & Ingestion**: It parses OpenAPI 3.x and Swagger 2.0 specs (JSON/YAML) to extract endpoints, path parameters, and expected request/response schemas.
> 2. **Active Exploit Engine**: Built with asynchronous Python (`httpx.AsyncClient`) and in-browser execution sockets, it tests endpoints against key OWASP API categories—such as rotating object IDs to detect BOLA/IDOR, forging unsigned `alg: none` JWTs, injecting administrative properties to detect Mass Assignment, and firing 20-30 req/s bursts to verify Rate Limiting.
> 3. **Exploit Chaining & CVSS Scoring**: It correlates isolated findings into composite attack paths (for example, combining a BOLA IDOR bug with Excessive Data Exposure to achieve full account takeover) and assigns mathematical CVSS v3.1 scores.
> 4. **Deliverable Generation & Persistence**: It saves historical scan records to an asynchronous SQLite database vault and generates professional, styled penetration testing reports for development teams.
> 
> I benchmarked the tool against official vulnerable applications like OWASP crAPI and OWASP vAPI, where it achieved a 100% detection rate across targeted categories while producing zero false positives on clean benchmark APIs like Swagger Petstore."

---

## 2. Problem Statement, Solution, and How Results Are Generated

### The Problem Statement
- **Shift in Attack Surface**: 80%+ of modern web traffic is pure API data exchange (JSON/REST). Endpoints, not HTML pages, control access to databases and business logic.
- **Legacy Scanners Fail on APIs**: Traditional DAST tools look for HTML forms and `<a>` links. They cannot guess required JSON payload structures or path parameters (e.g. `/api/v2/users/{id}`).
- **Manual Pentesting Doesn't Scale**: Manually testing dozens of endpoints in Burp Suite is time-consuming, and bugs like BOLA and Mass Assignment are frequently missed prior to production deployment.

### My Solution
- A **Spec-Aware Automated Pentest Framework** that reads machine-readable API contracts, parses their parameters, and automatically constructs and fires targeted exploit payloads.

### How the Tool Generates Results (The Exact Step-by-Step Technical Flow)
When an interviewer asks: *"How does your tool actually produce the vulnerability results?"*, explain this 4-step pipeline:

```
[ OpenAPI Spec (JSON/YAML) ]
             |
             v
   [ 1. Ingestion Layer ] ──> Extracts routes, params, methods & JSON schemas
             |
             v
   [ 2. Payload Mutation ] ──> Generates targeted exploit packets:
             |                 - Path Param Swapper: {id} -> '1' vs '2' (BOLA)
             |                 - Token Mutator: JWT header -> {"alg":"none"} (Broken Auth)
             |                 - Body Injector: {"is_admin": true, "role": "admin"} (Mass Assignment)
             |                 - Burst Dispatcher: 25 concurrent async HTTP requests (Rate Limit)
             |
             v
   [ 3. Network Execution ] ──> Fires genuine HTTP requests via httpx.AsyncClient / fetch sockets
             |
             v
   [ 4. Response Diffing ] ──> Evaluates live HTTP status codes & payload diffs:
             |                 - Confirms BOLA if ID 1 and ID 2 return HTTP 200 with distinct data
             |                 - Confirms Mass Assignment if server reflects injected 'is_admin'
             |                 - Confirms Rate Limit flaw if zero HTTP 429s returned
             |
             v
[ 5. Chaining & Output ] ──> Maps findings to CVSS v3.1 vectors, constructs kill-chain graphs,
                               persists records in SQLite DB, and exports HTML/PDF reports.
```

---

## 3. What Are the Results? (Metrics & Benchmark Validation)

When asked: *"What results did you achieve?"*, present these concrete validation benchmarks:

| Target API Benchmark | Nature of Target | Results & Detection Accuracy |
|---|---|---|
| **OWASP crAPI** (`owasp-crapi-spec.json`) | Vulnerable E-Commerce API | Successfully identified 100% of target vulnerabilities: BOLA on vehicles/orders, OTP brute-force, Mass Assignment, and Unauthenticated endpoints. |
| **ShopVulnerable Live Target** (`mock_target.py`) | Real Local REST API on port 8888 | Successfully executed live network socket exploits, dumped SSNs/password hashes, and elevated account privileges via Mass Assignment. |
| **Swagger Petstore** (Official Reference API) | Clean, Non-Vulnerable API | Produced **0 False Positives**, verifying that properly secured endpoints are not erroneously flagged. |
| **Performance Benchmark** | Concurrent Async Execution | Assessed an entire 20-endpoint API specification across 5 OWASP categories in under **4 seconds**. |

---

## 4. Deep-Dive: Target OWASP API Top 10 Vulnerabilities & Code Fixes

### A. Broken Object Level Authorization (BOLA / IDOR) — API1:2023
- **Root Cause**: The API relies on client-provided object IDs without verifying that the current session owns that resource.
- **How My Tool Detects It**:
  1. Identifies endpoints with path parameters like `/users/{userId}/profile`.
  2. Sends requests swapping the ID (`/users/1` vs `/users/2`) using the same user's token (or Account A token querying Account B data).
  3. Validates that both return HTTP 200 with distinct data payloads.
- **Code Fix**:
  ```python
  # Vulnerable
  @app.get("/api/v2/users/{user_id}/profile")
  async def get_profile(user_id: int):
      return db.query(User).filter(User.id == user_id).first()

  # Secure (Enforces Object Ownership)
  @app.get("/api/v2/users/{user_id}/profile")
  async def get_profile(user_id: int, current_user: User = Depends(get_current_user)):
      if current_user.id != user_id and current_user.role != "admin":
          raise HTTPException(status_code=403, detail="Access denied: Cross-tenant data forbidden")
      return db.query(User).filter(User.id == user_id).first()
  ```

---

### B. Broken Authentication — API2:2023
- **Root Cause**: Missing authentication middleware on administrative routes or accepting unsigned JWTs (`alg: none`).
- **How My Tool Detects It**:
  1. Invokes endpoints marked private without any `Authorization` header.
  2. Forges a JWT with `{"alg": "none", "typ": "JWT"}` and removes the cryptographic signature segment to test if the server validates signatures.
- **Code Fix**:
  ```python
  # Secure JWT Configuration
  jwt.decode(
      token,
      key=SECRET_KEY,
      algorithms=["HS256", "RS256"],  # Strict whitelist (forbids 'none')
      options={"verify_signature": True, "verify_exp": True}
  )
  ```

---

### C. Excessive Data Exposure — API3:2023
- **Root Cause**: Database models are serialized directly into JSON responses without filtering out sensitive attributes.
- **How My Tool Detects It**: Analyzes HTTP response bodies using regex patterns for sensitive attributes (`password_hash`, `ssn`, `credit_card`, `secret`, `api_key`).
- **Code Fix**:
  ```python
  # Secure DTO Schema (Excludes Internal Database Fields)
  class UserPublicDTO(BaseModel):
      id: int
      full_name: str
      email: str
      # Excludes ssn, password_hash, credit_card

  @app.get("/api/v2/users/{user_id}", response_model=UserPublicDTO)
  async def get_user(user_id: int):
      return db.query(User).filter(User.id == user_id).first()
  ```

---

### D. Unrestricted Resource Consumption (Missing Rate Limiting) — API4:2023
- **Root Cause**: Authentication, OTP, and password-reset endpoints process unlimited consecutive requests without throttling.
- **How My Tool Detects It**: Fires an asynchronous burst of 20–30 concurrent requests within 1 second and checks for missing HTTP 429 status codes and absent `X-RateLimit-*` headers.
- **Code Fix**:
  ```python
  # Redis Sliding-Window Rate Limiting Middleware
  from fastapi_limiter.depends import RateLimiter

  @app.post("/api/v2/auth/login", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
  async def login(req: LoginRequest):
      # Restricts to 5 attempts per minute per IP
      ...
  ```

---

### E. Mass Assignment — API6:2023
- **Root Cause**: Binding unvalidated client JSON payloads directly to internal database objects.
- **How My Tool Detects It**: Injects unwhitelisted administrative fields (`{"is_admin": true, "role": "admin", "balance": 999999}`) into `POST`/`PUT` requests and verifies if the server persists the altered state.
- **Code Fix**:
  ```python
  # Secure: Explicit Whitelisted Request DTO
  class ProfileUpdateDTO(BaseModel):
      full_name: Optional[str] = None
      email: Optional[str] = None
      # is_admin and role are strictly excluded from client input
  ```

---

## 5. Exploit Chaining: Compound Attack Paths

Interviewers often ask: *"How do individual bugs combine into a critical security compromise?"*

| Chain ID | Attack Sequence | Compound Impact | CVSS Score |
|---|---|---|---|
| **CHAIN-01** | **BOLA (API1)** ➔ **Data Leak (API3)** ➔ **Impersonation** | An attacker traverses user IDs to harvest all tenant password hashes and SSNs without triggering alerts. | **9.8 Critical** |
| **CHAIN-02** | **Broken Auth (API2)** ➔ **Mass Assignment (API6)** ➔ **Root Escalation** | Bypasses JWT validation via `alg: none` on profile update, injects `is_admin: true`, and escalates to permanent Superuser. | **9.9 Critical** |
| **CHAIN-03** | **No Rate Limit (API4)** ➔ **SMS OTP Brute Force** | Concurrent high-velocity burst requests iterate through all 10,000 4-digit OTP combinations in under 20 seconds, bypassing 2FA. | **8.8 High** |

---

## 6. Technical Interview Questions & Answers (FAQ)

### Q1: Why did you choose FastAPI and httpx over Flask and requests?
> **Answer**: "FastAPI provides native asynchronous route handlers, automatic OpenAPI schema generation, and high-performance JSON serialization via Pydantic. For the attack layer, `httpx` was chosen because it natively supports `asyncio` through `httpx.AsyncClient`. When executing rate-limiting burst tests or scanning multiple endpoints concurrently, non-blocking asynchronous I/O allows us to fire dozens of HTTP requests simultaneously on a single thread without blocking the event loop."

### Q2: How does the parser handle differences between OpenAPI 3.x and Swagger 2.0?
> **Answer**: "OpenAPI 3.x and Swagger 2.0 structure schemas differently:
> 1. **Request Bodies**: Swagger 2.0 places request bodies inside the `parameters` array with `in: 'body'`, whereas OpenAPI 3.x uses a dedicated `requestBody.content['application/json'].schema` object.
> 2. **Authentication**: Swagger 2.0 defines auth under `securityDefinitions` at the root, while OpenAPI 3.x groups them under `components.securitySchemes`.
> 3. **Host/Servers**: Swagger 2.0 separates `host`, `basePath`, and `schemes`, whereas OpenAPI 3.x uses a unified `servers: [{url: ...}]` array.
> My parser inspects the root version key and normalizes these differences into a unified `EndpointInfo` and `ParsedSpec` Pydantic model."

### Q3: How do you prevent false positives?
> **Answer**: "We verify findings through response validation diffs rather than relying purely on HTTP status codes:
> 1. **For BOLA**: We verify that accessing ID 1 and ID 2 returns HTTP 200 with distinct, non-trivial JSON bodies.
> 2. **For Mass Assignment**: We verify that the injected property (`is_admin: true`) is reflected with its updated value in the server response or persistence check.
> 3. **For Rate Limiting**: We check for both missing HTTP 429 status codes and the absence of standard rate-limiting headers (`X-RateLimit-*`, `Retry-After`).
> 4. **Benchmarking**: We validated the scanner against clean reference APIs (Swagger Petstore) to confirm zero false positives on clean endpoints."

### Q4: How is the CVSS v3.1 score calculated?
> **Answer**: "Each confirmed vulnerability is mapped to a standardized CVSS v3.1 Base Vector string. For example, BOLA is assigned:
> `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
> - **Attack Vector (AV)**: Network (N)
> - **Attack Complexity (AC)**: Low (L)
> - **Privileges Required (PR)**: Low (L)
> - **User Interaction (UI)**: None (N)
> - **Scope (S)**: Unchanged (U)
> - **Confidentiality (C)**: High (H)
> - **Integrity (I)**: High (H)
> - **Availability (A)**: None (N)
> This evaluates mathematically to a **Base Score of 8.6 (High Severity)**."

### Q5: How is persistence implemented?
> **Answer**: "The backend uses asynchronous SQLAlchemy (`AsyncSession` and `create_async_engine`) connected to SQLite/PostgreSQL. Concurrency is handled through `asyncio` and `httpx.AsyncClient` without blocking the main server thread. On the frontend, state is synced between the database API and persistent local storage to ensure historical scan records and findings persist across reloads."

---

## 7. Whiteboard Architecture Diagram Guide

When asked to sketch the architecture on a whiteboard, draw this clean 4-tier flow:

```
+-------------------------------------------------------------+
| 1. RECON & PARSING                                          |
|    OpenAPI / Swagger Spec ---> Spec Ingestion Engine        |
|                                ---> Normalized Endpoint Map |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 2. ACTIVE ATTACK ENGINE                                     |
|    Endpoint Map ---> Async Concurrent Socket Probes         |
|    - BOLA IDOR          - alg:none JWT Forge                |
|    - Burst Rate Limit   - Mass Assignment Injection         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 3. CORRELATION & CHAINING                                   |
|    Atomic Findings ---> Exploit Chaining Engine             |
|                    ---> Compound CVSS v3.1 Scoring          |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 4. PERSISTENCE & VISUALIZATION                              |
|    - Database Vault (SQLite ORM)                            |
|    - SVG Topology Node Graphs & Flowcharts                  |
|    - Client Pentest Report Exporter (HTML / PDF)            |
+-------------------------------------------------------------+
```

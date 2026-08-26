# Automated VAPT for Web APIs — Master Technical Interview Preparation Guide

This guide is structured to help you excel in **Application Security (AppSec)**, **Cybersecurity**, **Penetration Testing**, and **Backend/DevSecOps** technical interviews. It covers the project's core architecture, real-world attack techniques, deep vulnerability mechanics, database schema design, and counter-defenses.

---

## 1. 30-Second Elevator Pitch

> "I engineered an Automated Vulnerability Assessment and Penetration Testing (VAPT) Framework specifically tailored for Web APIs. Traditional scanners focus on HTML web pages and miss API business logic flaws. My tool ingests machine-readable OpenAPI 3.x and Swagger 2.0 specs, parses endpoints, parameters, and auth schemes, and actively executes concurrent network exploits across the OWASP API Security Top 10 (such as BOLA, Broken Auth, Mass Assignment, and Rate Limiting). It correlates isolated findings into multi-stage exploit chains (like BOLA leading to PII exfiltration and persistent account takeover), calculates standardized CVSS v3.1 base scores, renders interactive SVG attack topologies and kill-chain flowcharts, persists scan records in a dedicated database vault, and generates client-ready penetration testing deliverables with HTTP request/response proof-of-concept evidence."

---

## 2. System Architecture & Component Breakdown

```
+-------------------------------------------------------------------------+
|                              React Frontend                             |
|  - Attack Surface Visualizer       - Interactive Node Topology Graph    |
|  - Real-time Network Scan Console  - Kill-Chain Flowchart Visualizer    |
|  - CVSS Risk Breakdown Heatmap     - Pentest Report Generator / Export  |
+------------------------------------+------------------------------------+
                                     | REST API / Network Sockets
+------------------------------------v------------------------------------+
|                         FastAPI Backend Engine                          |
|                                                                         |
|  +--------------------+   +-----------------------+   +---------------+ |
|  |    Spec Parser     |   |   Attack Orchestrator |   |  CVSS Scorer  | |
|  | - OpenAPI 3.x      |-->| - Broken Auth Module  |-->| - CVSS v3.1   | |
|  | - Swagger 2.0      |   | - BOLA / IDOR Module  |   | - Vector Calc | |
|  | - Schema Extractor |   | - Rate Limit Probe    |   | - Severity    | |
|  +--------------------+   | - Mass Assignment     |   +---------------+ |
|            |              | - Data Exposure       |           |         |
|  +---------v----------+   +-----------------------+   +-------v-------+ |
|  |    Auth Handler    |               |               | Report Engine | |
|  | - Bearer / JWT     |   +-----------v-----------+   | - HTML / PDF  | |
|  | - Dual-Account Swap|   |   Exploit Chaining    |   | - Executive   | |
|  | - alg:none Forge   |   | - Multi-Stage Chains  |   |   Summary     | |
|  +--------------------+   +-----------------------+   +---------------+ |
+------------------------------------+------------------------------------+
                                     |
                             +-------v-------+
                             | SQLite / DB   |
                             | - Scan Vault  |
                             | - Findings    |
                             +---------------+
```

### Key Architectural Layers:
1. **Spec Ingestion & Normalization Layer**: Reads OpenAPI 3.0/3.1 and Swagger 2.0 (JSON & YAML) and maps them into unified `ParsedSpec`, `EndpointInfo`, and `ParameterInfo` Pydantic models.
2. **Dynamic Attack & Probing Layer**: Asynchronous `httpx.AsyncClient` socket runner and in-browser execution engine that dispatches concurrent HTTP requests.
3. **Correlation & Exploit Chaining Engine**: Identifies relationships between atomic findings to map out composite kill-chains.
4. **Scoring & Standardization Layer**: Automatically computes CVSS v3.1 vector strings and base metrics.
5. **Persistent Database Vault**: Async SQLAlchemy ORM with SQLite, auto-syncing with frontend storage for persistent scan history.

---

## 3. Deep-Dive: Target OWASP API Security Top 10 Vulnerabilities

### A. Broken Object Level Authorization (BOLA / IDOR) — API1:2023
- **Root Cause**: The API exposes object identifiers (`/api/v2/users/{userId}`) without checking if the user session has ownership rights over that specific record.
- **Exploitation Technique**:
  - *Single-Account Probing*: Traverses numeric/UUID IDs (`/users/1` vs `/users/2`) and diffs responses.
  - *Dual-Account Probing*: Authenticates as User A (Attacker) and requests User B's (Victim's) object ID. If status `200 OK` is returned with distinct tenant data, BOLA is confirmed.
- **Vulnerable Code Example**:
  ```python
  # Vulnerable Backend Implementation
  @app.get("/api/v2/users/{user_id}/profile")
  async def get_profile(user_id: int):
      return db.query(User).filter(User.id == user_id).first()
  ```
- **Remediation Code Example**:
  ```python
  # Secure Implementation
  @app.get("/api/v2/users/{user_id}/profile")
  async def get_profile(user_id: int, current_user: User = Depends(get_current_user)):
      # Enforce ownership check
      if current_user.id != user_id and current_user.role != "admin":
          raise HTTPException(status_code=403, detail="Forbidden: Cross-tenant access denied")
      return db.query(User).filter(User.id == user_id).first()
  ```

---

### B. Broken Authentication — API2:2023
- **Root Cause**: Unvalidated JWT cryptographic signatures, missing middleware on administrative routes, or accepting the `alg: none` header.
- **Exploitation Technique**:
  - *Missing Auth Check*: Strips the `Authorization` header and invokes endpoints marked protected.
  - *`alg: none` Signature Bypass*: Forges the JWT header to `{"alg": "none", "typ": "JWT"}` and removes the third segment (signature) to check if the parser accepts unsigned tokens.
- **Vulnerable Code Example**:
  ```python
  # Vulnerable JWT Verification
  jwt.decode(token, verify=False)  # Signature verification disabled!
  ```
- **Remediation Code Example**:
  ```python
  # Secure JWT Verification
  jwt.decode(
      token,
      key=SECRET_KEY,
      algorithms=["HS256", "RS256"],  # Strict algorithm whitelist
      options={"verify_signature": True, "verify_exp": True}
  )
  ```

---

### C. Excessive Data Exposure — API3:2023
- **Root Cause**: Developers serialize full ORM/database objects (including sensitive properties like password hashes, SSNs, credit cards, or internal keys) and rely on the frontend to filter what is shown.
- **Exploitation Technique**: Uses regex patterns to detect leaked attributes in response JSON (`password_hash`, `ssn`, `credit_card`, `secret`, `api_key`).
- **Remediation Code Example**:
  ```python
  # Secure DTO / Response Model Projection
  class UserPublicDTO(BaseModel):
      id: int
      full_name: str
      email: str
      # Omit ssn, password_hash, credit_card

  @app.get("/api/v2/users/{user_id}", response_model=UserPublicDTO)
  async def get_user(user_id: int):
      return db.query(User).filter(User.id == user_id).first()
  ```

---

### D. Unrestricted Resource Consumption (Missing Rate Limiting) — API4:2023
- **Root Cause**: Sensitive endpoints (e.g. `/auth/login`, `/auth/verify-otp`, `/auth/forget-password`) do not enforce throttling.
- **Exploitation Technique**: Fires an asynchronous burst of 20–30 concurrent requests within 1 second. Checks if all return HTTP 200/201 and verifies if `429 Too Many Requests`, `X-RateLimit-*`, or `Retry-After` headers are missing.
- **Remediation Code Example**:
  ```python
  # Redis Sliding-Window Rate Limiter Middleware
  from fastapi_limiter.depends import RateLimiter

  @app.post("/api/v2/auth/login", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
  async def login(req: LoginRequest):
      # Max 5 attempts per minute per IP
      ...
  ```

---

### E. Mass Assignment — API6:2023
- **Root Cause**: Directly mapping client JSON payload dictionaries to backend ORM entities without property whitelisting.
- **Exploitation Technique**: Injects unwhitelisted administrative fields (`{"is_admin": true, "role": "admin", "balance": 999999}`) into `POST`/`PUT` requests, then verifies if the modified attributes persist.
- **Remediation Code Example**:
  ```python
  # Vulnerable
  @app.put("/api/v2/users/{user_id}")
  async def update_user(user_id: int, req_data: dict):
      for key, val in req_data.items():
          setattr(user, key, val) # Modifies is_admin directly!

  # Secure
  class ProfileUpdateDTO(BaseModel):
      full_name: Optional[str] = None
      email: Optional[str] = None
      # is_admin and role are strictly excluded
  ```

---

## 4. Exploit Chaining: Compound Attack Paths

In security interviews, discussing **how vulnerabilities compound into a full breach** shows deep real-world understanding:

| Chain ID | Attack Flow (Kill-Chain Steps) | Real-World Impact | Compound CVSS |
|---|---|---|---|
| **CHAIN-01** | **BOLA (API1)** ➔ **Data Leak (API3)** ➔ **Impersonation** | An attacker iterates user IDs, extracts victim password hashes and SSNs, and takes over accounts without triggering alerts. | **9.8 Critical** |
| **CHAIN-02** | **Broken Auth (API2)** ➔ **Mass Assignment (API6)** ➔ **Root Takeover** | Bypasses JWT validation via `alg: none` on profile update, injects `is_admin: true`, and escalates to permanent Superuser. | **9.9 Critical** |
| **CHAIN-03** | **No Rate Limit (API4)** ➔ **SMS OTP Brute Force** | High-velocity concurrent probing iterates through all 10,000 4-digit OTP combinations in under 20 seconds, bypassing 2FA. | **8.8 High** |

---

## 5. Senior-Level Interview Questions & Answers

### Q1: Why is traditional DAST (like OWASP ZAP or generic web crawlers) ineffective against modern APIs?
> **Answer**: "Traditional DAST scanners rely on HTML anchor tags (`<a href>`), forms, and page rendering to crawl an application. Modern APIs are completely decoupled from the UI—they use JSON serialization, path parameters (`/users/{id}`), and token-based headers. Traditional scanners do not understand required payload schemas or HTTP methods (PUT, DELETE, PATCH). My tool is **spec-aware**: it ingests the OpenAPI schema, understands expected types and authentication requirements, and generates targeted, syntactically valid attack requests."

### Q2: What is the technical difference between OpenAPI 3.x and Swagger 2.0 schema parsing?
> **Answer**: "Swagger 2.0 and OpenAPI 3.x structure data differently:
> 1. **Request Bodies**: Swagger 2.0 places request bodies inside the `parameters` array with `in: 'body'`. OpenAPI 3.x uses a dedicated `requestBody.content['application/json'].schema` object.
> 2. **Authentication**: Swagger 2.0 defines auth under `securityDefinitions` at the root, while OpenAPI 3.x groups them under `components.securitySchemes`.
> 3. **Servers**: Swagger 2.0 splits host into `host`, `basePath`, and `schemes`, whereas OpenAPI 3.x uses a unified `servers: [{url: ...}]` array.
> My parser inspects the root version key and normalizes these differences into a single unified Pydantic data model."

### Q3: How do you verify vulnerabilities without causing false positives?
> **Answer**: "We verify findings with response diffing rather than relying purely on HTTP status codes:
> 1. **BOLA Verification**: We verify that accessing ID 1 and ID 2 returns HTTP 200 with distinct, non-trivial JSON bodies.
> 2. **Mass Assignment Verification**: We verify that the injected property (`is_admin: true`) is reflected with its updated value in the server response or persistence check.
> 3. **Rate Limiting**: We check for both missing HTTP 429 status codes and the absence of standard rate-limiting headers (`X-RateLimit-*`, `Retry-After`).
> 4. **Benchmarking**: We validated the engine against both vulnerable APIs (crAPI, vAPI) and clean reference APIs (Swagger Petstore) to confirm zero false positives on clean endpoints."

### Q4: How does the CVSS v3.1 scoring algorithm work in your tool?
> **Answer**: "Each finding is mapped to a standardized CVSS v3.1 Vector String. For example, BOLA is assigned:
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

### Q5: How did you implement database persistence and concurrency?
> **Answer**: "The backend uses asynchronous SQLAlchemy (`AsyncSession` and `create_async_engine`) connected to SQLite/PostgreSQL. Concurrency is handled through `asyncio` and `httpx.AsyncClient` without blocking the main server thread. On the frontend, state is synced between the database API and persistent local storage to ensure historical scan records and findings persist across reloads."

---

## 6. Whiteboard Architecture Diagram Guide

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

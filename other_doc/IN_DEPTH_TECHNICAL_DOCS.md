# Automated VAPT for Web APIs — In-Depth Architectural & Engineering Documentation

This document provides a comprehensive, component-by-component deep dive into the **Automated Vulnerability Assessment and Penetration Testing (VAPT) Framework for Web APIs**. It details the underlying mathematical formulas, networking models, parsing algorithms, exploit payload mutations, state management, database schema design, and counter-defenses.

---

## Table of Contents
1. [Core Architectural Blueprint](#1-core-architectural-blueprint)
2. [Spec Ingestion & Normalization Engine](#2-spec-ingestion--normalization-engine)
3. [The Dynamic Exploit & Attack Engine](#3-the-dynamic-exploit--attack-engine)
   - [A. Broken Object Level Authorization (BOLA / IDOR)](#a-broken-object-level-authorization-bola--idor)
   - [B. Broken Authentication & JWT Signature Flaws](#b-broken-authentication--jwt-signature-flaws)
   - [C. Unrestricted Resource Consumption (Rate Limiting)](#c-unrestricted-resource-consumption-rate-limiting)
   - [D. Mass Assignment Privilege Escalation](#d-mass-assignment-privilege-escalation)
   - [E. Excessive Data Exposure & Schema Diffing](#e-excessive-data-exposure--schema-diffing)
4. [Exploit Chaining & Multi-Stage Kill-Paths](#4-exploit-chaining--multi-stage-kill-paths)
5. [Mathematical CVSS v3.1 Scoring Engine](#5-mathematical-cvss-v31-scoring-engine)
6. [Data Persistence & SQLite ORM Vault](#6-data-persistence--sqlite-orm-vault)
7. [Frontend Architecture, State Synchronization & Visualizations](#7-frontend-architecture-state-synchronization--visualizations)
8. [Live Network Target Environment & Benchmarking](#8-live-network-target-environment--benchmarking)
9. [Edge Cases, Error Handling & False Positive Elimination](#9-edge-cases-error-handling--false-positive-elimination)

---

## 1. Core Architectural Blueprint

The framework implements a clean separation of concerns across a 4-tier model:

```
[ OpenAPI 3.x / Swagger 2.0 Spec (JSON / YAML) ]
                       |
                       v
+-------------------------------------------------------------------------+
| Layer 1: Ingestion, AST Parsing & Attack Surface Normalization          |
| - Identifies HTTP methods, route parameters, request/response schemas   |
| - Extracts securitySchemes (Bearer JWT, API Keys, Basic Auth)           |
+-------------------------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------------------------+
| Layer 2: Targeted Payload Mutation & Asynchronous Exploit Runner        |
| - Async network sockets via Python httpx.AsyncClient / fetch Sockets    |
| - Single-Account ID traversal & Dual-Account token swapping             |
| - alg:none JWT signature stripper & administrative field fuzzer         |
| - Concurrent burst dispatcher (20–30 req/s)                             |
+-------------------------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------------------------+
| Layer 3: Response Diffing, Exploit Chaining & CVSS v3.1 Calculator      |
| - Status code validation + live response diffing (Eliminates FPs)       |
| - Multi-stage kill-chain correlation (BOLA -> PII Leak -> Account Takeover)
| - Formal CVSS v3.1 Base Vector string generation                        |
+-------------------------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------------------------+
| Layer 4: Storage, SVG Visualizations & Deliverable Reporting            |
| - Persistent Async SQLAlchemy SQLite Vault                              |
| - SVG Microservice Node Graphs, Sequence Diagrams, Risk Heatmaps        |
| - Client-Ready HTML/PDF Penetration Testing Report Exporter             |
+-------------------------------------------------------------------------+
```

---

## 2. Spec Ingestion & Normalization Engine

### A. The Challenge: OpenAPI 3.x vs. Swagger 2.0 Inconsistencies
APIs define their structures differently across versions:
1. **Request Body**:
   - *Swagger 2.0*: Placed inside the `parameters` array with `"in": "body"`.
   - *OpenAPI 3.x*: Placed in a separate `"requestBody": { "content": { "application/json": { "schema": { ... } } } }` block.
2. **Authentication Schemes**:
   - *Swagger 2.0*: Root-level `"securityDefinitions": { ... }`.
   - *OpenAPI 3.x*: Nested under `"components": { "securitySchemes": { ... } }`.
3. **Host & Base Path**:
   - *Swagger 2.0*: Split into `"host": "api.domain.com"`, `"basePath": "/v1"`, and `"schemes": ["https"]`.
   - *OpenAPI 3.x*: Unified into `"servers": [{ "url": "https://api.domain.com/v1" }]`.

### B. Implementation Details (`spec_parser.py` & `specParser.js`)
The parser normalizes all specifications into uniform internal models:
- **`EndpointInfo`**:
  - `path`: `str` (e.g. `/api/v2/users/{userId}`)
  - `method`: `str` (GET, POST, PUT, DELETE, PATCH)
  - `parameters`: `List[ParameterInfo]` (Location: path, query, header)
  - `request_body_schema`: `Optional[Dict[str, Any]]` (JSON Schema object properties)
  - `response_schema`: `Optional[Dict[str, Any]]` (Expected HTTP 200/201 schemas)
  - `auth_required`: `bool` (Determined by evaluating operation-level and global `security` arrays)
  - `auth_schemes`: `List[str]` (Specific scheme names like `bearerAuth`)

---

## 3. The Dynamic Exploit & Attack Engine

Rather than relying on static code analysis (SAST) or blind fuzzing, the framework uses **Spec-Aware Dynamic Exploit Probing**.

---

### A. Broken Object Level Authorization (BOLA / IDOR)
**File**: `app/attacks/bola.py` & `realAttackEngine.js`  
**OWASP Classification**: API1:2023

#### 1. Technical Mechanics:
BOLA occurs when an endpoint relies on a client-supplied object ID (`/users/{id}`) without verifying that the requesting user's session token has authorization over that object.

#### 2. Exploit Algorithm:
1. Regex matches all path parameters: `r"\{[^\}]+\}"` (e.g. `{userId}`, `{orderId}`).
2. **Dual-Account Mode** (Deterministic Cross-Tenant Check):
   - Authenticates as **Account A (Attacker)**.
   - Issues an HTTP request to **Account B's (Victim's)** resource ID (`/api/v2/users/2/profile`).
   - If HTTP 200 is returned with Account B's data payload, BOLA is confirmed.
3. **Single-Account Mode** (ID Traversal Probe):
   - Replaces parameter with ID `1` and ID `2`.
   - Issues requests:
     $$\text{Req}_1 = \text{GET } /users/1 \quad \text{and} \quad \text{Req}_2 = \text{GET } /users/2$$
   - Computes the string distance and payload difference:
     $$\text{Diff}(\text{Res}_1, \text{Res}_2) > \text{Threshold} \land \text{Status}(\text{Res}_1) = 200 \land \text{Status}(\text{Res}_2) = 200$$
   - Confirms horizontal privilege escalation if distinct data is returned across unowned identifiers.

#### 3. Defensive Countermeasure:
```python
# Contextual Database Query Enforcement
@app.get("/api/v2/users/{user_id}/profile")
async def get_profile(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Tenant separation violation")
    return db.query(User).filter(User.id == user_id).first()
```

---

### B. Broken Authentication & JWT Signature Flaws
**File**: `app/attacks/broken_auth.py` & `core/security.py`  
**OWASP Classification**: API2:2023

#### 1. Technical Mechanics:
1. **Unprotected Administrative Route Discovery**: Identifies routes with administrative keywords (`/admin/`, `/system/`, `/audit-logs`) that omit security requirements (`security: []`).
2. **`alg: none` Signature Bypass**: Exploits libraries that support the `none` algorithm per RFC 7518 without enforcing cryptographic signing.

#### 2. The `alg: none` Exploit Transformation:
A standard JWT consists of three Base64URL-encoded segments separated by periods:
$$\text{Header}.\text{Payload}.\text{Signature}$$

The mutator performs the following transformation:
1. Decodes the header and forces algorithm to `none`:
   $$\text{Header}_{\text{forged}} = \text{Base64Url}(\text{JSON.stringify}(\{"alg": "none", "typ": "JWT"\}))$$
2. Modifies the payload (e.g. sets `"role": "admin"`, `"is_admin": true`).
3. Strips the signature segment:
   $$\text{JWT}_{\text{forged}} = \text{Header}_{\text{forged}} \mathbin{\Vert} \text{"."} \mathbin{\Vert} \text{Payload}_{\text{forged}} \mathbin{\Vert} \text{"."}$$
4. Sends the forged token to protected endpoints. If the server responds with HTTP 200/201, signature verification is compromised.

---

### C. Unrestricted Resource Consumption (Rate Limiting)
**File**: `app/attacks/rate_limit.py`  
**OWASP Classification**: API4:2023

#### 1. Technical Mechanics:
APIs handling authentication, registration, or password recovery must throttle high-velocity requests to prevent credential stuffing and brute-force attacks.

#### 2. Exploit Algorithm:
1. Identifies sensitive routes: keywords like `login`, `register`, `otp`, `password`, `reset`, `token`.
2. Uses `asyncio.gather` with `httpx.AsyncClient` to dispatch 25–30 concurrent requests within $\Delta t < 1.5\text{s}$.
3. Evaluates response headers and status codes:
   - Evaluates if HTTP `429 Too Many Requests` is present.
   - Evaluates the presence of rate-limiting headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.
   - If zero 429s are returned and $\ge 90\%$ of requests succeed, the vulnerability is flagged.

---

### D. Mass Assignment Privilege Escalation
**File**: `app/attacks/mass_assignment.py`  
**OWASP Classification**: API6:2023

#### 1. Technical Mechanics:
Mass Assignment occurs when client-provided JSON keys are automatically mapped into backend domain entities without property whitelisting.

#### 2. Exploit Mutation Matrix:
The module injects the following security-sensitive attributes into `POST`, `PUT`, and `PATCH` payloads:
- `{"is_admin": true}`
- `{"isAdmin": true}`
- `{"role": "admin"}`
- `{"role": "superuser"}`
- `{"verified": true}`
- `{"balance": 999999.0}`
- `{"permissions": ["admin", "all"]}`

#### 3. Verification Diffing:
The tool verifies vulnerability only if the server returns HTTP 200/201 **and** the response JSON reflects the injected property, confirming persistence.

---

### E. Excessive Data Exposure & Schema Diffing
**File**: `app/attacks/excessive_data.py`  
**OWASP Classification**: API3:2023

#### 1. Technical Mechanics:
Backend queries often select entire database rows (`SELECT * FROM users`) and serialize them directly, relying on frontend code to discard sensitive properties.

#### 2. Regex Attribute Extraction Matrix:
The engine inspects raw HTTP response JSON against sensitive attribute patterns:
- Passwords & Hashes: `(?i)\bpassword\b|\bpassword_hash\b`
- Personally Identifiable Information: `(?i)\bssn\b|\bsocial_security\b`
- Financial Records: `(?i)\bcredit_card\b|\bcard_number\b|\bcvv\b`
- Authentication & Payment Tokens: `(?i)\btoken\b|\bsecret\b|\bapi_key\b|\bpayment_token\b`

---

## 4. Exploit Chaining & Multi-Stage Kill-Paths

Individual vulnerabilities often appear low or medium in isolation. When chained, they can lead to complete system compromise.

```
+--------------------------------------------------------------------+
| Kill-Chain 1: BOLA + Excessive Data Exposure                       |
| [1. Traverse ID] ──> [2. Extract PII/Hash] ──> [3. Account Takeover]|
+--------------------------------------------------------------------+

+--------------------------------------------------------------------+
| Kill-Chain 2: Broken Auth + Mass Assignment                        |
| [1. alg:none Forge] ──> [2. Inject isAdmin] ──> [3. Superuser Escalation]|
+--------------------------------------------------------------------+

+--------------------------------------------------------------------+
| Kill-Chain 3: Missing Rate Limit + Weak OTP                        |
| [1. Burst 30 req/s] ──> [2. 10,000 OTP Keys] ──> [3. 2FA Bypass]   |
+--------------------------------------------------------------------+
```

### Correlation Logic (`exploit_chaining.py` & `exploitChain.js`)
The engine iterates through all identified atomic findings, constructs an adjacency graph of complementary vulnerabilities, and computes a **Compound CVSS Score**:
- If `BOLA` (8.6) + `Data Exposure` (7.5) $\longrightarrow$ Evaluates to **9.8 Critical (Account Takeover)**.
- If `Broken Auth` (9.1) + `Mass Assignment` (7.5) $\longrightarrow$ Evaluates to **9.9 Critical (Root Administrative Escalation)**.

---

## 5. Mathematical CVSS v3.1 Scoring Engine

The Common Vulnerability Scoring System (CVSS) calculates an open standard numerical score representing security severity.

### Mathematical Formula Breakdown:
The Base Score is computed from three primary sub-scores:
1. **Impact Sub-Score (ISS)**:
   $$\text{ISS} = 1 - \left[ (1 - \text{Impact}_{\text{Conf}}) \times (1 - \text{Impact}_{\text{Integ}}) \times (1 - \text{Impact}_{\text{Avail}}) \right]$$
2. **Impact Score**:
   - If Scope is Unchanged:
     $$\text{Impact} = 6.42 \times \text{ISS}$$
   - If Scope is Changed:
     $$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$
3. **Exploitability Sub-Score**:
   $$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$
4. **Base Score Calculation**:
   $$\text{BaseScore} = \text{Roundup}\left( \min(\text{Impact} + \text{Exploitability}, 10) \right)$$

### Mapped Framework Vectors:
| Category | CVSS v3.1 Vector String | Base Score | Severity |
|---|---|---|---|
| **BOLA / IDOR** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.6** | High |
| **Broken Auth** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1** | Critical |
| **Data Exposure** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| **Rate Limiting** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` | **5.3** | Medium |
| **Mass Assignment** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` | **7.5** | High |

---

## 6. Data Persistence & SQLite ORM Vault

**File**: `app/db/models.py` & `app/db/session.py`

### Entity-Relationship Diagram:
```
+------------------------------------+          +------------------------------------+
|               SCANS                |          |              FINDINGS              |
+------------------------------------+          +------------------------------------+
| id (PK, Integer)                   | 1      * | id (PK, Integer)                   |
| name (String)                      |<--------+| scan_id (FK -> scans.id)           |
| target_url (String)                |          | title (String)                     |
| status (Enum: pending, running, ..)|          | category (String)                  |
| total_endpoints (Integer)          |          | severity (Enum: critical, high, ..)|
| total_findings (Integer)           |          | cvss_score (Float)                 |
| created_at (DateTime UTC)          |          | cvss_vector (String)               |
| started_at (DateTime UTC)          |          | endpoint (String)                  |
| completed_at (DateTime UTC)        |          | method (String)                    |
+------------------------------------+          | description (Text)                 |
                                                | evidence (Text - HTTP PoC)         |
                                                | remediation (Text - Developer Fix) |
                                                +------------------------------------+
```

### Asynchronous Session Handling:
```python
# Async Engine & Session Factory
engine = create_async_engine("sqlite+aiosqlite:///./vapt.db", echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
```

---

## 7. Frontend Architecture, State Synchronization & Visualizations

The React 19 frontend uses responsive design tokens, persistent state synchronization, and fully data-driven SVG visualizations.

### A. Dual-Mode State Synchronization (`AppContext.jsx`):
1. **Local Persistent Storage**: Caches scan runs and active specs to `localStorage` under `vapt_scans_history_v1`.
2. **Backend DB Sync**: When the FastAPI server is running, the context auto-merges local storage with the backend SQLite database via `GET /api/v1/scans/`.

### B. Data-Driven Security Visualizations (`SecurityDiagrams.jsx`):
All four visualizations are **fully dynamic** — driven by actual scan findings, exploit chains, and parsed spec data. No hardcoded values.

1. **Attack Surface Topology Graph**: Auto-generates SVG service cluster nodes from `parsedSpec.endpoints` grouped by path prefix. Compromised nodes are severity-colored (critical = red, high = orange, medium = yellow) based on live findings. Secure nodes render green.
2. **Kill-Chain Flowchart**: Renders actual `exploitChains[]` array returned by the correlation engine. Each chain displays its numbered steps, OWASP tags, composite CVSS score, and remediation guidance. Shows an empty-state shield when no chains are correlated.
3. **OWASP Risk Heatmap**: Category distribution bars computed from `findings.filter()` with no fallback values. Bar widths are proportional to the maximum category count. Each bar displays affected endpoint paths. Categories with zero findings are hidden.
4. **Security Posture Scorecard**: An SVG circular gauge with a dynamic **Security Index** ($0 - 100$) computed as:
   $$\text{Score} = \max(0, 100 - (\text{Critical} \times 25 + \text{High} \times 15 + \text{Medium} \times 8 + \text{Low} \times 3))$$
   Grade scale: A ($\ge 90$), B ($\ge 75$), C ($\ge 50$), D ($\ge 25$), F ($\lt 25$). Metric cards dynamically compute attack surface exposure percentage, peak CVSS, confidentiality threat (detects leaked field types from evidence text), integrity threat, and availability threat.

---

## 8. Live Network Target Environment & Benchmarking

### A. Mock Target Server
**File**: `app/mock_target.py`  
Runs locally on `http://127.0.0.1:8888` to provide a functional test environment without external dependencies:

```
                  +----------------------------------------------+
                  |           Mock Target API Server             |
                  |                (Port: 8888)                  |
                  +----------------------------------------------+
                                         |
     +-------------------+---------------+-------------------+--------------------+
     |                   |                                   |                    |
     v                   v                                   v                    v
[/auth/login]    [/users/{id}/profile]             [/users/{id}/profile]    [/admin/audit-logs]
(No Rate Limit)  (BOLA IDOR + SSN Leaks)          (Mass Assign is_admin)    (Unauthenticated)
```

### B. Sample Specification Library (6 Specs)
The framework ships with a curated library of 6 OpenAPI specifications covering three testing tiers:

| Spec | Type | OWASP Coverage |
|---|---|---|
| `owasp-crapi-spec.json` | Vulnerable | BOLA, IDOR, OTP brute force (20+ endpoints) |
| `vulnerable-ecommerce-api.json` | Vulnerable | All 5 implemented OWASP categories |
| `vampi-vulnerable-api.json` | Vulnerable | BOLA, Broken Auth, Mass Assignment, Data Exposure, SQLi |
| `dvws-node-vulnerable-api.json` | Vulnerable | Injection, Auth Bypass, File Upload, Path Traversal, BFLA |
| `reqres-api-spec.json` | Non-Vulnerable | False-positive validation benchmark |
| `sample-api-spec.json` | Baseline | Parser verification and schema extraction |

---

## 9. Edge Cases, Error Handling & False Positive Elimination

1. **Clean Baseline Benchmarking**: The engine was validated against both the reference **Swagger Petstore API** and the **Reqres.in** hosted REST API to ensure properly secured endpoints produce zero false positives across multiple non-vulnerable targets.
2. **Graceful Degradation**: If the target server is unreachable over live network sockets, the scanner gracefully falls back to spec-based static heuristic analysis, ensuring results are always generated.
3. **CORS & Network Timeout Resilience**: All async network requests are wrapped with timeouts ($10\text{s}$) and safe exception handlers to prevent scan interruption on unreachable routes.
4. **Dynamic Visualization Safety**: All four security diagrams handle empty-state gracefully — when no findings exist, they display informative shield icons and messages instead of blank or broken charts.

---

*This document serves as the technical reference for the architecture, threat modeling, and implementation details of the Automated VAPT Framework for Web APIs.*

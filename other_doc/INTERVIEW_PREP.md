# Automated VAPT for Web APIs — Technical Interview Preparation Guide

This document provides a comprehensive technical breakdown of the project architecture, design choices, vulnerability detection algorithms, and answers to common security engineering and software development interview questions.

---

## 1. Executive Summary & Pitch (30-Second Elevator Pitch)

> "I built an Automated Vulnerability Assessment and Penetration Testing (VAPT) Framework for Web APIs. Unlike legacy scanners that crawl HTML pages and miss API-level business logic bugs, my tool ingests OpenAPI and Swagger specifications to construct machine-readable attack surface maps. It actively executes concurrent HTTP network exploits across the OWASP API Security Top 10—such as BOLA, Broken Auth, Mass Assignment, and Rate Limiting flaws—chains isolated findings into multi-stage kill paths (like BOLA to PII leak to Account Takeover), calculates standardized CVSS v3.1 scores, and generates client-ready penetration testing reports with live request/response proof-of-concept evidence."

---

## 2. Key Differentiators (Why is this project unique?)

1. **Spec-Aware Reconnaissance**: It does not blindly brute-force URL directories; it parses OpenAPI 3.x and Swagger 2.0 specs to discover hidden endpoints, path parameters, and expected payload types automatically.
2. **Exploit Chaining Engine**: Rather than reporting isolated bugs, it correlates findings to demonstrate compounded impact (e.g. an IDOR bug + an Excessive Data Exposure bug creates a full tenant impersonation scenario).
3. **Dual-Execution Mode**: Supports both a high-concurrency asynchronous backend scanner (`FastAPI` + `httpx`) and an in-browser live network execution engine (`fetch` sockets).
4. **Interactive Security Visualizations**: Features dynamic SVG network topology graphs, kill-chain sequence diagrams, and risk heatmaps.
5. **Standardized Scoring**: Implements CVSS v3.1 vector calculations rather than subjective severity labels.

---

## 3. Deep-Dive: The 5 Target OWASP API Top 10 Vulnerabilities

### A. Broken Object Level Authorization (BOLA / IDOR) — API1:2023
- **What it is**: An endpoint receives an object identifier (e.g. `/users/{id}`) and accesses data without validating whether the authenticated user owns that specific object.
- **How my tool detects it**:
  1. Identifies endpoints with path parameters matching `{id}`, `{userId}`, `{orderId}`.
  2. In Dual-Account Mode: Sends a request using Account A's JWT token to fetch Account B's resource ID (`/users/2`).
  3. In Single-Account Mode: Traverses adjacent numeric identifiers (`/users/1` vs `/users/2`) and diffs responses. If both return HTTP 200 with distinct data payloads, BOLA is confirmed.
- **Remediation**: Implement authorization checks at the database/data-access layer:
  ```python
  # Vulnerable
  user = db.query(User).filter(User.id == user_id).first()
  
  # Secure
  user = db.query(User).filter(User.id == user_id, User.tenant_id == current_user.tenant_id).first()
  ```

---

### B. Broken Authentication — API2:2023
- **What it is**: Missing authentication checks, unvalidated JWT signatures, or accepting expired/tampered tokens.
- **How my tool detects it**:
  1. **Unprotected Private Routes**: Sends unauthenticated HTTP requests to endpoints marked `security: []` or admin routes; flags if status 200 OK is returned.
  2. **`alg: none` Signature Bypass**: Takes a valid JWT, changes the header to `{"alg": "none", "typ": "JWT"}`, removes the cryptographic signature segment, and fires the forged token to check if the server blindly trusts unsigned payloads.
- **Remediation**: Explicitly configure JWT libraries to reject `none` algorithm tokens and enforce strict algorithm whitelisting (`algorithms=["RS256"]`).

---

### C. Excessive Data Exposure — API3:2023
- **What it is**: The backend queries full database objects and returns them directly to the client, relying on frontend code to filter what is displayed.
- **How my tool detects it**:
  1. Inspects HTTP response JSON payloads using regex heuristics searching for sensitive attributes: `password_hash`, `ssn`, `credit_card`, `secret`, `api_key`, `phone`.
  2. Compares returned JSON keys against documented OpenAPI response DTO schemas.
- **Remediation**: Use strict response serializer schemas (e.g., FastAPI `response_model` or Pydantic DTOs) to filter out internal database attributes before returning HTTP responses.

---

### D. Lack of Rate Limiting / Unrestricted Resource Consumption — API4:2023
- **What it is**: Sensitive authentication, registration, or OTP endpoints that accept infinite requests without throttling.
- **How my tool detects it**:
  1. Identifies authentication routes (`/login`, `/register`, `/otp`, `/verify-otp`).
  2. Dispatches an asynchronous burst of 20–30 concurrent HTTP requests in under 2 seconds.
  3. Inspects response headers for `X-RateLimit-*` and `Retry-After` headers, and verifies if any HTTP 429 Too Many Requests responses were triggered.
- **Remediation**: Implement IP and account-based sliding window rate limiters (e.g., Redis token bucket with a max of 5 requests per minute per IP on `/login`).

---

### E. Mass Assignment — API6:2023
- **What it is**: Client-supplied JSON body parameters are bound directly to internal data models without property whitelisting.
- **How my tool detects it**:
  1. Identifies mutating endpoints (`POST`, `PUT`, `PATCH`).
  2. Injects unadvertised privileged properties: `{"is_admin": true, "role": "admin", "balance": 999999}`.
  3. Inspects the subsequent response or state changes to verify if the server accepted and persisted the injected attributes.
- **Remediation**: Use explicit Data Transfer Objects (DTOs) with field whitelisting rather than binding raw request dictionaries to database models.

---

## 4. Exploit Chaining: Compound Attack Scenarios

In security interviews, explaining **how bugs combine** demonstrates senior-level understanding:

| Kill-Chain | Atomic Bugs Involved | Compound Impact |
|---|---|---|
| **Chain 1** | BOLA (API1) + Excessive Data Exposure (API3) | **Mass Account Takeover**: Attacker iterates IDs to harvest all tenant password hashes and SSNs without perimeter alerts. |
| **Chain 2** | Broken Auth (API2) + Mass Assignment (API6) | **Unauthenticated Root Escalation**: Attacker bypasses auth and injects `is_admin: true` to gain permanent superuser control. |
| **Chain 3** | Lack of Rate Limiting (API4) + Weak OTP | **2FA SMS Bypass**: Attacker brute-forces a 4-digit OTP (10,000 combinations) in under 20 seconds. |

---

## 5. Technical Questions & Answers (Interview FAQ)

### Q1: Why did you choose FastAPI and httpx for the backend?
> **Answer**: "FastAPI provides native asynchronous route handlers, OpenAPI schema generation, and high-speed JSON serialization via Pydantic. For the attack layer, `httpx` was chosen over `requests` because it natively supports `asyncio` (`httpx.AsyncClient`). When performing rate limit burst testing and concurrent endpoint sweeps, asynchronous I/O allows us to fire dozens of HTTP requests concurrently on a single thread without blocking the event loop."

### Q2: How does the OpenAPI parser handle differences between OpenAPI 3.x and Swagger 2.0?
> **Answer**: "OpenAPI 3.x and Swagger 2.0 structure schemas differently. For example, Swagger 2.0 stores body parameters inside the `parameters` array with `in: 'body'`, whereas OpenAPI 3.x uses a dedicated `requestBody.content['application/json'].schema` object. Similarly, auth schemes are defined under `securityDefinitions` in Swagger 2.0 versus `components.securitySchemes` in OpenAPI 3.x. My parser inspects the root key (`openapi` vs `swagger`) and routes the raw JSON/YAML to specialized adapter functions that normalize everything into a unified `EndpointInfo` and `ParsedSpec` data model."

### Q3: How do you prevent false positives during automated scanning?
> **Answer**: "We validate findings using response verification diffs rather than regex matches alone:
> 1. For BOLA, we verify that two distinct IDs return different non-trivial data payloads under valid HTTP 200 responses.
> 2. For Mass Assignment, we verify that the injected key is reflected with its altered value in the response JSON.
> 3. We also benchmarked the scanner against the official Swagger Petstore API (a clean, non-vulnerable API) to verify that clean endpoints are not falsely flagged."

### Q4: How is the CVSS v3.1 score calculated?
> **Answer**: "Each confirmed vulnerability is mapped to a standard CVSS v3.1 Base Vector string. For example, BOLA is assigned `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`. The score is calculated using standard metrics: Attack Vector (Network), Attack Complexity (Low), Privileges Required (Low), User Interaction (None), Scope (Unchanged), Confidentiality (High), Integrity (High), and Availability (None), resulting in an 8.6 High score."

### Q5: How do you handle authentication during scans?
> **Answer**: "The tool implements an `AuthHandler` module supporting Bearer/JWT tokens, API keys (header or query param), and HTTP Basic Auth. For BOLA testing, it supports a `DualAccountAuth` structure containing credentials for Account A (attacker) and Account B (victim), enabling automated token swapping during cross-account probes."

---

## 6. Project Architecture Diagram for Whiteboard Interviews

Be ready to draw this on a whiteboard:

```
[ OpenAPI Spec (JSON/YAML) ]
             |
             v
  [ Spec Ingestion Engine ]
             |
             +---> [ Structured Attack Surface Map ]
                         |
      +------------------+------------------+
      |                  |                  |
      v                  v                  v
 [ BOLA Probe ]   [ Auth & JWT ]    [ Rate Limit Probe ]
 (ID Traversal)   (alg:none forge)  (Concurrent Burst)
      |                  |                  |
      +------------------+------------------+
                         |
                         v
              [ Exploit Chaining Engine ]
             (Correlates Multi-Stage Paths)
                         |
                         v
              [ CVSS v3.1 Calculator ]
                         |
                         v
          [ Pentest Report & UI Visualizer ]
```

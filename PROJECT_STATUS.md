# 📊 Automated VAPT for Web APIs — Project Progress & Next Steps

---

## 📌 1. Project Overview & Current State

Is project ka aim ek **automated, spec-aware API Penetration Testing Framework** banana hai jo OpenAPI/Swagger specs ko ingest karke **OWASP API Top 10 vulnerabilities** ko actively test kare aur evidence-backed PoC ke sath CVSS-scored reports generate kare.

---

## ✅ 2. Abhi Tak Kya Complete Ho Chuka Hai (Current Progress)

### 🔹 Architecture & Scaffolding
- **Project Structure**: Full modular separation across `backend/` (FastAPI), `frontend/` (React + Vite), `docker/` (vulnerable targets), aur `samples/`.
- **Git Ignore & Config**: Ready with `.gitignore`, environment variable templates (`.env.example`), and Pytest config (`pytest.ini`).

### 🔹 Backend Architecture (FastAPI & Python 3.11+)
- **Spec Parser (`spec_parser.py`)**:
  - OpenAPI 3.x & Swagger 2.0 specs ko parse karta hai.
  - Endpoints, methods, parameters (path, query, body), aur request/response schemas extract karta hai.
  - Auth schemes (Bearer/JWT, API Key, Basic Auth) detect karta hai.
  - Unit tests written (`tests/test_spec_parser.py`) covering all versions and edge cases.
- **Database & ORM (`db/models.py`, `db/session.py`)**:
  - Async SQLAlchemy setup with SQLite.
  - Models for `Scan` (status, target, timestamps, counts) and `Finding` (severity, CVSS, endpoint, evidence, remediation).
- **Security & Auth (`core/security.py`, `services/auth_handler.py`)**:
  - JWT claim inspection, unverified decoding, expiration checks, aur `alg: none` signature forge utility.
  - Dual-Account auth wrapper (Account A vs Account B swap) ready for BOLA testing.
- **CVSS v3.1 Scoring Engine (`reports/cvss_scorer.py`)**:
  - Automatic base vector mapping for BOLA, Broken Auth, Excessive Data Exposure, Rate Limiting, and Mass Assignment.
- **REST API Endpoints (`api/v1/`)**:
  - `/api/v1/specs/parse` & `/api/v1/specs/parse-url` (Spec Ingestion).
  - `/api/v1/scans/` (Create, List, Details, Run trigger).
  - `/api/v1/reports/` (Report generation trigger).

### 🔹 Frontend Application (React 18 + Vite)
- **Design System (`index.css`)**:
  - Premium Dark Cyber Aesthetic with custom tokens, glow effects, badge styles, and responsive cards.
- **Page Layout & Routing (`components/Layout.jsx`, `App.jsx`)**:
  - Sidebar navigation with icons connecting all 5 views.
- **Spec Upload & Parser (`pages/SpecUpload.jsx`, `utils/specParser.js`)**:
  - Drag-and-drop file upload + URL fetch mode.
  - **Live Client-side Parser** capable of parsing specs instantaneously without waiting for backend dependencies.
- **Interactive Endpoint Map (`pages/EndpointMap.jsx`)**:
  - Visual breakdown by HTTP methods (GET, POST, PUT, DELETE, PATCH).
  - Auth protection filters (Protected 🔒 vs Exposed 🔓).
  - Expandable rows detailing path parameters, required fields, and request/response schemas.
- **Dashboard (`pages/Dashboard.jsx`)**:
  - Live metric counters connected to uploaded specs.

### 🔹 Test Infrastructure
- **Docker Compose (`docker/docker-compose.yml`)**:
  - Configured for **OWASP crAPI** (Port 8888), **OWASP vAPI** (Port 7777), and **Swagger Petstore** (Port 8081).
- **Sample Dataset (`samples/sample-api-spec.json`)**:
  - Ready-to-use vulnerable API spec demonstrating realistic routes.

---

## 📋 3. Components Summary Table

| Module / Component | Status | Description |
|---|---|---|
| **Spec Ingestion Engine** | ✅ Complete | Parses OpenAPI 3.x / Swagger 2.0 (JSON & YAML) |
| **Attack Surface Visualizer** | ✅ Complete | Interactive React UI with filters & expandable schemas |
| **Auth & Token Management** | ✅ Complete | JWT handling & Account A/B auth swapping |
| **CVSS v3.1 Calculator** | ✅ Complete | Computes scores & severity from vulnerability vectors |
| **Database Storage** | ✅ Complete | SQLite schema for scan runs & vulnerability findings |
| **Docker Target Environments** | ✅ Complete | crAPI & vAPI setup ready in Docker Compose |
| **Attack Execution Engine** | 🟡 In Progress | Attack modules designed, need live HTTP exploit logic |
| **Chained Exploitation** | ⏳ Pending | Linking findings (e.g., BOLA ➔ Data Exposure) |
| **PDF / HTML Pentest Reporting** | ⏳ Pending | Client-ready report export with PoC requests |

---

## 🚀 4. Aage Kya Karna Hai (Next Steps & Roadmap)

Hum **Phase 1 (Spec Ingestion & Recon UI)** complete kar chuke hain. Next target **Phase 2: Vulnerability Detection & Active Attack Modules** hai.

### 🎯 Step 1: Active Attack Engine Implementation (Phase 2 Priority)

1. **Broken Authentication Module (`attacks/broken_auth.py`)**:
   - Test endpoints with missing auth headers on protected routes.
   - Send forged `alg: none` tokens to check if server accepts unsigned JWTs.
   - Send expired JWTs to verify timestamp validation.

2. **BOLA (Broken Object Level Authorization) Module (`attacks/bola.py`)**:
   - Identify endpoints containing path parameters (`/api/users/{id}`, `/api/orders/{order_id}`).
   - Fire requests using **Account A's token** to fetch **Account B's resource ID**.
   - Check if response returns `200 OK` with sensitive cross-account data.

3. **Rate Limiting Probe (`attacks/rate_limit.py`)**:
   - Send rapid concurrent burst requests (30–50 requests) against login/OTP endpoints using `httpx.AsyncClient`.
   - Flag if no `429 Too Many Requests` or throttling headers are returned.

4. **Mass Assignment Fuzzer (`attacks/mass_assignment.py`)**:
   - Inject privilege fields (`isAdmin: true`, `role: "admin"`) into `POST`/`PUT` JSON bodies.
   - Verify if server persists modified attributes.

5. **Excessive Data Exposure Module (`attacks/excessive_data.py`)**:
   - Match API response payload keys against documented OpenAPI schemas.
   - Flag internal leaks (passwords, tokens, SSNs, credit cards, stack traces).

---

### 🎯 Step 2: Scan Console & Live Execution (Frontend ↔ Backend Integration)

1. Connect the **Scan Console UI** (`pages/ScanConsole.jsx`) to backend async scan runner via WebSockets or polling.
2. Display live progress logs (e.g., `[+] Probing /users/{id} for BOLA... VULNERABLE`).

---

### 🎯 Step 3: Reporting & Polish (Phase 3)

1. **Jinja2 + WeasyPrint Engine**: Generate downloadable executive PDF / HTML reports with:
   - Executive Summary with severity charts (Pie/Bar).
   - Detailed PoC HTTP Request / Response evidence.
   - Actionable Developer Remediation guides & CVSS score breakdown.

# Automated VAPT for Web APIs — Project Status and Capability Report

---

## 1. Project Overview

**Automated VAPT for Web APIs** is an automated vulnerability assessment and penetration testing framework designed to ingest OpenAPI/Swagger specifications, map API attack surfaces, execute targeted dynamic exploits across OWASP API Security Top 10 vulnerabilities, correlate multi-stage exploit chains, persist historical scan vaults in SQLite, and generate CVSS v3.1 scored penetration testing deliverables.

---

## 2. Capability Matrix and Implementation Status

| Component / Layer | Status | Technical Details |
|---|---|---|
| **Spec Ingestion Engine** | **Completed** | Full parser for OpenAPI 3.x and Swagger 2.0 (JSON & YAML) with automatic auth extraction, schema normalization, and unit tests (`pytest`). |
| **Attack Surface Visualizer** | **Completed** | Reactive React 19 interface with HTTP method filters, auth protection toggles, and expandable parameter schemas. |
| **Broken Authentication Module** | **Completed** | Probes unauthenticated routes and executes `alg: none` unsigned JWT forgery attacks. |
| **BOLA / IDOR Module** | **Completed** | Traverses object identifiers and executes single-account and dual-account cross-access checks. |
| **Rate Limiting Probe** | **Completed** | Dispatches asynchronous concurrent burst requests (20-30 req/s) detecting missing HTTP 429 and missing throttling headers. |
| **Mass Assignment Fuzzer** | **Completed** | Injects privilege escalation attributes (`is_admin: true`, `role: admin`) into JSON mutation requests. |
| **Excessive Data Exposure Auditor** | **Completed** | Inspects live payloads against expected response schemas for leaked PII (SSNs, secrets, credit cards, password hashes). |
| **Exploit Chaining Engine** | **Completed** | Correlates isolated atomic findings into composite kill-chains (e.g. BOLA -> Data Leak -> Account Takeover). |
| **Interactive Security Diagrams** | **Completed** | Fully data-driven: Attack surface topology (auto-generated from endpoints), kill-chain flowchart (from correlated chains), OWASP risk heatmap (from real findings), and security posture scorecard (dynamic 0-100 gauge with Grade A-F). No hardcoded values. |
| **CVSS v3.1 Scoring Calculator** | **Completed** | Standard CVSS v3.1 Base Vector string generation and score calculations (Critical, High, Medium, Low). |
| **Persistent Database Vault** | **Completed** | Persistent storage for lifetime scan runs, historical findings, CVSS records, search filtering, and deletion controls. |
| **Pentest Report Generator** | **Completed** | Exports formatted executive HTML/PDF penetration testing reports with PoC request/response snippets and remediation code. |
| **Live Vulnerable Target Server** | **Completed** | Standalone FastAPI mock server (`mock_target.py`) running on port 8888 for local, zero-Docker network exploit testing. |
| **Sample Spec Library (6 Specs)** | **Completed** | OWASP crAPI, E-Commerce Fintech, VAmPI, DVWS-node (4 vulnerable) + Reqres.in (1 non-vulnerable false-positive benchmark) + Sample baseline (1 parser verification). |
| **Docker Test Targets** | **Completed** | Docker Compose with OWASP crAPI, OWASP vAPI, and Swagger Petstore containers. |
| **Automated Test Suite** | **Completed** | pytest coverage for OpenAPI 3.x and Swagger 2.0 spec parsers. |

---

## 3. Execution and Testing Flow

### Step 1: Start Target Application
```powershell
# Option A: Standalone Mock Target Server (No Docker required)
cd backend
python app/mock_target.py
```
*Runs on `http://127.0.0.1:8888`.*

### Step 2: Start Web Interface
```powershell
cd frontend
npm run dev
```
*Access interface at `http://localhost:5173`.*

### Step 3: Run Full VAPT Workflow
1. Navigate to **Upload Spec** and load `samples/owasp-crapi-spec.json` or `samples/vulnerable-ecommerce-api.json`.
2. Review mapped routes on the **Endpoint Map**.
3. Open **Scan Console** and click **Fire Live Exploit Scan**.
4. Inspect real-time network logs, interactive topology diagrams, and kill-chain flowcharts.
5. Review **Database Vault** on the **Dashboard** and **Reports** tab to inspect historical records and export client-ready penetration testing deliverables.

---

## 4. Benchmark Validation Summary

| Target | Type | Findings |
|---|---|---|
| OWASP crAPI | Vulnerable | 100% detection across BOLA, OTP, Mass Assignment |
| Mock Target (Live) | Vulnerable | Live network exploits, SSN dump, privilege escalation |
| VAmPI | Vulnerable | BOLA, Broken Auth, Mass Assignment, Data Exposure |
| DVWS-node | Vulnerable | BFLA, BOLA, Injection, Mass Assignment |
| Swagger Petstore | Non-Vulnerable | 0 False Positives |
| Reqres.in | Non-Vulnerable | 0 False Positives |

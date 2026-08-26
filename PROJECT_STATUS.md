# 📊 Automated VAPT for Web APIs — Project Progress & Architecture Report

---

## 📌 1. Project Overview

**Automated VAPT for Web APIs** is an end-to-end, spec-aware vulnerability assessment and penetration testing engine built to identify, verify, chain, and report high-impact security vulnerabilities across the **OWASP API Security Top 10 (2023)** framework.

---

## 🏆 2. Full Project Capabilities Matrix

| Feature / Capability | Status | Description |
|---|---|---|
| **Spec Ingestion Engine** | ✅ **Complete** | Parses OpenAPI 3.x / Swagger 2.0 (JSON & YAML) with automatic auth extraction |
| **Interactive Attack Surface Map** | ✅ **Complete** | React 18 UI with method filters, auth toggles, and expandable parameter schemas |
| **Broken Auth Detector** | ✅ **Complete** | Probes missing tokens on private routes and crafts `alg: none` unsigned JWT attacks |
| **BOLA / IDOR Detector** | ✅ **Complete** | Traverses object identifiers and conducts single/dual-account cross-access checks |
| **Rate Limiting Probe** | ✅ **Complete** | Concurrent burst probe (30 req/s) detecting missing HTTP 429 & throttling headers |
| **Mass Assignment Fuzzer** | ✅ **Complete** | Injects privilege escalation attributes (`isAdmin`, `role: superuser`) into request bodies |
| **Excessive Data Exposure Auditor**| ✅ **Complete** | Inspects live payloads against schemas for PII (SSNs, secrets, credit cards) |
| **Exploit Chaining Engine** | ✅ **Complete** | Correlates atomic bugs into composite kill-chains (e.g. BOLA ➔ Data Leak ➔ Account Takeover) |
| **CVSS v3.1 Scoring Calculator** | ✅ **Complete** | Real-time CVSS base vectors & score calculator (Critical, High, Medium, Low) |
| **Client-Ready Pentest Reporter** | ✅ **Complete** | Formats and exports professional executive HTML/PDF pentest deliverables with PoC |
| **Docker Test Environments** | ✅ **Complete** | Docker Compose configurations for OWASP crAPI, OWASP vAPI, and Swagger Petstore |

---

## 🛠️ 3. How to Run and Test

### 1. Web Application (Frontend)
```powershell
cd frontend
npm run dev
```
Open `http://localhost:5173`.

### 2. Run an Assessment:
1. Go to **Upload Spec** and upload `samples/vulnerable-ecommerce-api.json`.
2. Click **Parse & Map Endpoints** to view the live attack surface map.
3. Open **Scan Console** and click **Start Scan**.
4. Switch between **Atomic Findings** and **Exploit Chains & Kill Paths** tabs to inspect correlated multi-stage attack graphs with PoC evidence.
5. Open **Reports** and click **Export Pentest Report** to download the corporate security audit document.

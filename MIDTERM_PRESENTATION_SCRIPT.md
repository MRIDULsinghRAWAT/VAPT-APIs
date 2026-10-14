# Mid-Term Presentation & Live Demo Guide (VAPT for Web APIs)

> **Phase 1 Deliverables (Completed)**: Spec Parsing + Recon, Auth Engine, BOLA (API1), Broken Authentication (API2), React UI, Mock Test Bench.
> **Phase 2 Roadmap (Planned)**: Remaining 3 OWASP Modules, CVSS v3.1 Scoring, Multi-Stage Exploit Chaining, Persistent SQLite Scan Vault, and Automated PDF/HTML Reports.

---

## 👥 1. Team Script (Strictly 2 Lines Each)

### **Member 1 (Intro & Problem)**
- **Line 1:** "Our project is an Automated VAPT Framework for Web APIs based on the OWASP API Security Top 10."
- **Line 2:** "For Phase 1 (Mid-Term), we built the core architecture, OpenAPI spec parser, and automated detection for the first two attack modules: BOLA and Broken Authentication."

### **Member 2 (Recon & Auth Engine)**
- **Line 1:** "I worked on the spec parser that automatically ingests OpenAPI JSON/YAML to extract endpoints, HTTP methods, and parameter schemas."
- **Line 2:** "Our auth handler supports Bearer JWTs, API keys, and automated dual-account token swapping to detect cross-tenant access violations."

### **Member 3 (Attack Modules & Validation)**
- **Line 1:** "I developed the exploit modules for API1 (BOLA/IDOR object traversal) and API2 (Broken Auth via unauthenticated routes and `alg:none` token forgery)."
- **Line 2:** "Every confirmed vulnerability automatically records real HTTP request and response proof-of-concept evidence."

### **Member 4 (Frontend Dashboard, Demo & Phase 2 Outlook)**
- **Line 1:** "I developed the React dashboard featuring the attack surface map, live scan console, and the local vulnerable test bench (`mock_target.py`)."
- **Line 2:** "In Phase 2, we will integrate CVSS v3.1 scoring, 3 more attack modules, and exploit chaining — now let’s jump into the live demo."

---

## 🖥️ 2. Live Demo Script (What to Show & What to Say)

| Step | Screen | Action | What to Say (1 Line) |
|---|---|---|---|
| **Step 1** | **Upload Spec** (`/upload`) | Select/Upload preloaded OpenAPI spec | *"Framework automatically parses the API contract and maps out all endpoints."* |
| **Step 2** | **Endpoint Map** (`/endpoints`) | Show routes with GET/POST badges & Protected tags | *"It classifies the attack surface into public and protected authenticated routes."* |
| **Step 3** | **Scan Console** (`/scan`) | Select **BOLA** & **Broken Auth**, click **Start Scan** | *"The engine fires dual-token IDOR requests and `alg:none` forged JWTs against live endpoints."* |
| **Step 4** | **Findings & Evidence** | Open detected vulnerability card | *"Vulnerability is confirmed with actual request headers and response payloads as PoC proof."* |
| **Step 5** | **Phase 2 Wrap-up** | Point to Phase 2 scope | *"Phase 1 is functional; Phase 2 expands into exploit chaining, CVSS scoring, and automated reporting."* |

---

## 🚀 3. Phase 2 Roadmap: What We Will Do Next

| Category | Component | Description / Planned Deliverable |
|---|---|---|
| **Attack Engine** | **3 More OWASP Modules** | • **API3: Excessive Data Exposure**: Compare responses against schema to detect leaked PII/tokens.<br>• **API4: Missing Rate Limiting**: Burst tests (20–30 req/sec) to verify HTTP 429 throttling.<br>• **API6: Mass Assignment**: Inject non-whitelisted fields (`is_admin: true`, `role: admin`) in create/update payloads. |
| **Scoring** | **CVSS v3.1 Scoring Engine** | Calculate standardized base scores, vector strings, and severity ratings (Critical/High/Medium/Low) for every finding. |
| **Exploitation** | **Multi-Stage Exploit Chaining** | Automatically correlate isolated flaws into real attack kill-chains (e.g., **BOLA + Excessive Data Exposure** $\rightarrow$ Account Takeover; **Broken Auth + Mass Assignment** $\rightarrow$ Privilege Escalation). |
| **Persistence** | **Scan Vault (Database)** | Save complete scan history, vulnerability snapshots, timestamps, and full HTTP evidence into an asynchronous SQLite database. |
| **Reporting** | **Automated Report Generator** | Export professional, audit-ready **PDF and HTML penetration testing reports** with executive summaries, CVSS breakdown, and developer remediation fix guides. |
| **Benchmarking** | **Evaluation & Accuracy** | Benchmark detection accuracy and measure false positives against OWASP crAPI, OWASP vAPI, and non-vulnerable control targets (Swagger Petstore). |

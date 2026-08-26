# Automated Vulnerability Assessment and Penetration Testing Framework for Web APIs

An automated, spec-aware security assessment framework designed to ingest OpenAPI/Swagger specifications, map API attack surfaces, execute targeted dynamic exploits across OWASP API Security Top 10 vulnerabilities, correlate multi-stage exploit chains, and generate CVSS v3.1 scored penetration testing deliverables.

---

## Technical Overview

Modern cloud architectures have transitioned their primary attack surface to the REST/GraphQL API layer. Traditional web application vulnerability scanners often rely on HTML crawling and heuristics tailored for monolithic web pages, frequently failing to parse modern API specifications, object-level authorization models, or JSON-serialized business logic.

This framework bridges that gap by implementing a spec-aware recon and exploit engine. It ingests machine-readable API contracts (OpenAPI 3.x / Swagger 2.0), constructs structured endpoint maps, actively executes targeted payloads against live endpoints, captures real HTTP status/payload diffs as proof-of-concept evidence, chains interrelated findings into full kill paths, and exports client-ready penetration testing reports.

---

## System Architecture

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
                             | - Scan Runs   |
                             | - Findings    |
                             +---------------+
```

---

## Core Capabilities

### 1. Spec Ingestion and Reconnaissance
- Ingests OpenAPI 3.x and Swagger 2.0 specifications in JSON and YAML formats.
- Extracts endpoints, HTTP methods, path/query/header parameters, and JSON request/response schemas.
- Maps authentication mechanisms including Bearer JWT, API Keys, and Basic Auth.
- Provides interactive filtering by HTTP method and public versus protected authorization states.

### 2. Active Vulnerability Audit Modules (OWASP API Top 10)
- **Broken Object Level Authorization (API1:2023)**: Executes object identifier traversal and dual-account token swapping to verify cross-tenant access boundaries.
- **Broken Authentication (API2:2023)**: Probes unauthenticated administrative routes and crafts tokens with the `none` algorithm to test cryptographic signature enforcement.
- **Excessive Data Exposure (API3:2023)**: Compares live response payloads against expected DTO schemas and scans for leaked sensitive attributes (passwords, tokens, SSNs, credit card numbers).
- **Unrestricted Resource Consumption / Missing Rate Limiting (API4:2023)**: Dispatches high-velocity burst requests (20–30 req/s) to authentication/OTP routes to detect missing HTTP 429 throttling.
- **Mass Assignment (API6:2023)**: Injects non-whitelisted administrative attributes (`is_admin: true`, `role: admin`, elevated account balances) into JSON mutation requests.

### 3. Exploit Chaining and Kill-Chain Analysis
- Correlates isolated atomic findings into composite attack paths:
  - *Chain 1:* BOLA + Excessive Data Exposure -> Full Identity Theft and Account Takeover.
  - *Chain 2:* Broken Auth + Mass Assignment -> Unauthenticated Superuser Escalation.
  - *Chain 3:* Missing Rate Limiting + Weak Auth -> Automated 2FA OTP Bypass.
- Calculates compound CVSS metrics and displays step-by-step kill-chain graphs.

### 4. Interactive Security Visualizations
- **Attack Surface Node Graph**: Interactive SVG topology depicting communication flows between Client, API Gateway, Microservices, and Databases, highlighting compromised routes.
- **Kill-Chain Flowchart**: Sequence diagram of multi-stage exploit paths with animated connectors.
- **OWASP API Risk Heatmap**: Exposure breakdown by vulnerability category.
- **Security Posture Scorecard**: Gauge index (0-100) reflecting overall perimeter posture.

### 5. Automated Pentest Reporting
- Generates downloadable HTML/PDF deliverables with Executive Summaries, Risk Matrix, PoC Request/Response snippets, and developer patch guidelines.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend Engine | Python 3.11+, FastAPI, Pydantic | Spec ingestion, routing, asynchronous attack engine |
| Attack Layer | httpx (Async HTTP), custom token mutators | High-concurrency network probing and socket tests |
| Frontend | React 18, Vite, Lucide Icons | Reactive UI, attack surface visualizer, console |
| Scoring Engine | CVSS v3.1 Standard Library | Base score calculation, metric vector generation |
| Persistence | SQLite / Async SQLAlchemy | Storage of scan metadata, historical results, and evidence |
| Testing Infrastructure | Docker Compose (crAPI, vAPI, Petstore) | Controlled environments for validation |

---

## Quick Start Guide

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher
- Git

### 1. Backend Setup

```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env   # On Windows: copy .env.example .env
uvicorn app.main:app --reload --port 8000
```

- API Documentation: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

- Web Interface: `http://localhost:5173`

### 3. Standalone Live Vulnerable Target (Optional Testing Host)

For running live network exploits locally without Docker:

```bash
cd backend
python app/mock_target.py
```
This starts a live vulnerable REST API on `http://127.0.0.1:8888`.

### 4. Docker Test Targets (Optional)

```bash
cd docker
docker compose up -d
```

| Container | Port | Description |
|---|---|---|
| OWASP crAPI | 8888 | Vulnerable e-commerce application |
| OWASP vAPI | 7777 | OWASP API Top 10 target |
| Swagger Petstore | 8081 | Non-vulnerable benchmark for false-positive validation |

---

## Verification and Testing

Execute the automated test suite covering OpenAPI 3.x and Swagger 2.0 parsers:

```bash
cd backend
pytest -v
```

---

## Documentation References

- [PROJECT_STATUS.md](file:///c:/Users/Mridul/Desktop/VAPT%20for%20Web%20APIs/other_doc/PROJECT_STATUS.md) — Comprehensive technical capability matrix and status overview.
- [INTERVIEW_PREP.md](file:///c:/Users/Mridul/Desktop/VAPT%20for%20Web%20APIs/other_doc/INTERVIEW_PREP.md) — Technical interview guide covering architecture decisions, bug deep-dives, and FAQ.

---

## License

This project is licensed under the MIT License.

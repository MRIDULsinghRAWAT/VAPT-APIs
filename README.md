# Automated VAPT for Web APIs

> An Automated Vulnerability Assessment & Penetration Testing Framework for Web APIs

---

## Overview

**Automated VAPT for Web APIs** is a specialized security framework designed to ingest OpenAPI/Swagger specifications (or captured HTTP traffic), map the complete attack surface, and **actively execute targeted exploits** across key OWASP API Security Top 10 categories:

1. **BOLA (Broken Object Level Authorization)** — Cross-account ID/resource swapping
2. **Broken Authentication** — JWT validation flaws, signature bypass, and weak sessions
3. **Excessive Data Exposure** — Identifying undocumented internal object leaks in API responses
4. **Lack of Rate Limiting** — Automated burst probing against auth/sensitive routes
5. **Mass Assignment** — Privilege escalation fuzzing with injected administrative fields

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                          │
│  (Endpoint Map · Live Scan Console · Report Viewer · Dashboard)│
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API
┌──────────────────────────▼──────────────────────────────────────┐
│                      FastAPI Backend                            │
│  ┌──────────┐  ┌──────────────┐  ┌───────────┐  ┌───────────┐ │
│  │  Spec    │  │   Attack     │  │  Scoring  │  │ Reporting │ │
│  │  Parser  │→ │   Engine     │→ │  (CVSS)   │→ │ (PDF/HTML)│ │
│  └──────────┘  └──────────────┘  └───────────┘  └───────────┘ │
│       ↓              ↓                                         │
│  ┌──────────┐  ┌──────────────┐                                │
│  │  Auth    │  │  Exploit     │                                │
│  │  Handler │  │  Chaining    │                                │
│  └──────────┘  └──────────────┘                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   SQLite    │
                    │   Database  │
                    └─────────────┘
```

---

## Tech Stack

| Layer | Choice |
|---|---|
| **Backend Engine** | Python 3.11+, FastAPI, Pydantic |
| **Attack Layer** | httpx (Async HTTP), custom token mutation & payload injectors |
| **Frontend** | React 18, Vite, Lucide Icons |
| **Scoring & Reporting** | CVSS v3.1 scoring, Jinja2 / WeasyPrint (HTML/PDF export) |
| **Storage** | SQLite (Dev) / PostgreSQL (Prod), SQLAlchemy async ORM |
| **Testing Infrastructure** | Docker Compose (crAPI, vAPI, Petstore) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose *(optional, for local vulnerable practice targets)*

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

- API Docs (Swagger UI): `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

- Web Interface: `http://localhost:5173`

### 3. Vulnerable Test Targets (Docker)

```bash
cd docker
docker compose up -d
```

| Target | Port | Type |
|---|---|---|
| **OWASP crAPI** | `8888` | Vulnerable e-commerce API |
| **OWASP vAPI** | `7777` | OWASP API Top 10 target |
| **Swagger Petstore** | `8081` | Clean API (False positive testing) |

---

## Project Roadmap

- [x] **Phase 1 — Spec Ingestion & Recon Engine**
  - OpenAPI 3.x & Swagger 2.0 parser (JSON/YAML)
  - Interactive attack surface endpoint map & filter console
  - Authentication scheme detection (Bearer/JWT, API Key, Basic)
- [ ] **Phase 2 — Vulnerability Detection & Exploit Engine**
  - BOLA automated ID/token swap testing
  - Broken Auth & JWT validation auditing
  - Excessive Data Exposure response diffing
  - Rate limiting burst probe
  - Mass assignment privilege escalation fuzzing
- [ ] **Phase 3 — Reporting & Scoring**
  - Automated CVSS v3.1 vulnerability scoring
  - Professional pentest-style PDF / HTML report generator
  - Scan history and remediation guidance

---

## Legal & Ethical Disclaimer

> [!WARNING]
> This tool is strictly developed for **educational purposes, defensive auditing, and authorized penetration testing**. Only test systems you own or have explicit, written authorization to evaluate. The authors are not responsible for any misuse of this tool.

---

## License

MIT License

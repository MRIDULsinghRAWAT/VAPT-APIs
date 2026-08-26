# Automated VAPT for Web APIs

> An Automated Vulnerability Assessment & Penetration Testing Framework for Web APIs

**By:** Mridul Singh Rawat | B.Tech CSE — Cybersecurity & Digital Forensics

---

## Overview

This tool ingests an OpenAPI/Swagger spec (or captured traffic), builds a live map of every endpoint/parameter/auth requirement, then **actively attacks** that map across 5 focused OWASP API Top 10 categories:

1. **BOLA** — Broken Object Level Authorization
2. **Broken Authentication** — JWT/session weaknesses
3. **Excessive Data Exposure** — over-returning data
4. **Rate Limiting** — brute-forceable endpoints
5. **Mass Assignment** — privilege escalation via unexpected fields

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

## Tech Stack

| Layer | Choice |
|---|---|
| Backend / Engine | Python 3.11+, FastAPI |
| Attack Layer | httpx (async), custom auth-swap & payload-mutation modules |
| Frontend | React 18, Vite |
| Reporting | CVSS v3.1 scoring, PDF/HTML export |
| Storage | SQLite (dev) / PostgreSQL (prod) |
| Test Infra | Docker Compose — vulnerable target APIs |

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (for test targets)

### Backend Setup

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### Test Targets (Docker)

```bash
cd docker
docker-compose up -d
```

This starts crAPI and vAPI locally for safe testing.

## Project Phases

- **Phase 1** — Spec Ingestion & Recon Engine (Weeks 1–4)
- **Phase 2** — Vulnerability Detection & Exploit Engine (Weeks 5–9)
- **Phase 3** — Reporting, Scoring & Polish (Weeks 10–12)

## Legal & Ethical

This tool is for **authorized testing only**. Never target production systems without explicit written authorization. The tool enforces an authorization checkbox before any scan starts.

## License

MIT

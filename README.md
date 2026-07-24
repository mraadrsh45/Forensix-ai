# ForensiX AI 🛡️🔍
> **Enterprise-Grade Digital Forensics & Threat Intelligence Platform**
check website https://forensix-ai-zeta.vercel.app
ForensiX AI is a cloud-native, AI-driven platform built for security operations centers (SOCs), digital forensics examiners, and threat analysts. It unifies advanced threat intelligence lookup, deep forensic artifact analysis (files, network, memory, mobile), and AI-driven automated investigations into a single intuitive glassmorphism-inspired interface.

---

## 🏗️ Architecture & Tech Stack

ForensiX AI is built as a microservice/multi-container application consisting of a modern frontend, a powerful REST API, and numerous threat intelligence & storage integrations.

```mermaid
graph TD
    Client[Web Browser / Next.js SPA] <-->|HTTP / WebSockets| API[FastAPI Backend]
    API -->|Relational Data| DB[(PostgreSQL)]
    API -->|Entity Relationships| GraphDB[(Neo4j)]
    API -->|Log Indexing & Search| ES[(Elasticsearch)]
    API -->|Caching & PubSub| Cache[(Redis)]
    API -->|Evidence Files Store| ObjectStorage[(AWS S3 / MinIO)]
    API -->|AI Reasoning & Agentic Analysis| Gemini[Gemini AI]
    API -->|Enrichment Services| ExternalAPIs[VirusTotal, AbuseIPDB, SecurityTrails, Urlscan]
```

### Frontend (`/forensix-ai`)
- **Framework**: Next.js 15 (React 19) with App Router
- **Language**: TypeScript
- **Styling**: TailwindCSS & Custom CSS
- **Features**: Interactive threat maps, real-time live threat telemetry stream over WebSockets, incident case management dashboard, file & memory analysis submission portals.

### Backend (`/backend`)
- **Framework**: FastAPI (Python 3.10+)
- **Async Execution**: Asyncio & Uvicorn
- **Object Relational Mapper**: SQLAlchemy 2.0
- **Third-Party API Integrations**: VirusTotal, AbuseIPDB, SecurityTrails, WhoisXML, URLScan.io
- **AI Engine**: Gemini Pro / Flash API integration for automated investigations, summaries, and agentic threat mitigation pipelines.

---

## ⚡ Core Features

*   **🌐 Global Threat Intelligence Center (GTIC)**: Real-time WebSocket threat event stream, interactive geolocation maps, and threat category distributions.
*   **🩺 Deep Forensic Modules**:
    *   *Email Forensics*: Parse EML/MSG files, check headers, hop locations, SPF/DKIM/DMARC records, and scan embedded attachments.
    *   *File & Malware Analysis*: Extract metadata, compute hashes, run YARA rules, and retrieve VirusTotal sandbox reports.
    *   *Network Forensics*: Upload PCAP files to perform protocol analysis, track conversation flows, and spot anomalous traffic patterns.
    *   *Memory & Mobile Forensics*: Volatility-based profile generation and memory-dump parsing; Android/iOS backup and artifact inspection.
*   **🤖 AI Investigation & Copilot**: Automated threat graph-construction, case summaries, log/payload analysis, and natural language interactive prompt queries.
*   **📑 Case & PDF Report Manager**: Group assets, IOCs, and timelines into structured cases. Export forensic reports to print-ready PDF format.

---

## 🚀 Getting Started

### Prerequisites
- [Docker & Docker Compose](https://www.docker.com/) (Recommended)
- [Python 3.10+](https://www.python.org/downloads/)
- [Node.js 18+](https://nodejs.org/)

---

### Method 1: Spin up using Docker Compose (Recommended)

1. **Configure Environment Variables**:
   Create a `.env` file in the root directory (or update the default values in `docker-compose.yml`):
   ```bash
   VIRUSTOTAL_API_KEY=your_virustotal_key
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   GEMINI_API_KEY=your_gemini_key
   DATABASE_URL=postgresql://user:password@host/db
   ```

2. **Build and Start**:
   ```bash
   docker compose up --build -d
   ```

3. **Access Services**:
   - **Frontend App**: [http://localhost:3000](http://localhost:3000)
   - **Backend API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Method 2: Manual Local Development Setup

#### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a python virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure your `.env` file based on `.env.example`.
5. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

#### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd forensix-ai
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Run the Next.js development server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🔌 API Documentation Summary

The API endpoints are grouped logically under `/api/v1/`:

| Endpoint Prefix | Description |
| :--- | :--- |
| `/api/v1/auth` | User authentication, registration, JWT tokens |
| `/api/v1/cases` | Forensic incident management and log timelines |
| `/api/v1/gtic` | Global Threat Intelligence dashboard data and WebSockets (`/ws`) |
| `/api/v1/ip-intel` | IP address reputation analysis (AbuseIPDB, VirusTotal, etc.) |
| `/api/v1/domain-intel` | Domain whois, passive DNS, DNS records, and registrar data |
| `/api/v1/website-intel` | Webpage screenshots, active screenshots, and HTML analyzer |
| `/api/v1/email-forensics` | Parse `.eml`/`.msg`, security validation checks |
| `/api/v1/file-analysis` | File uploads, static binary inspections, and hashing |
| `/api/v1/malware-analysis` | Dynamic threat scanning and YARA/Sandboxing pipelines |
| `/api/v1/network-forensics` | PCAP uploads and network traffic conversation parsing |
| `/api/v1/ai-investigation` | Gemini AI-driven automated analysis and response |

---

## 🔒 Security & Compliance
- **Data Protection**: Encryption in transit (TLS/HTTPS) and REST API security via OAuth2 password flow with JWT tokens.
- **Evidence Integrity**: SHA-256 hash generation on upload for all digital evidence file objects to guarantee chain-of-custody verification.

---

## 🚀 Roadmap & Version Releases

### Version 1.0.1 (Next Release)
*   **Deep Forensic Module Activation**: Full integration of the local forensics engine core including:
    *   *Memory Forensics*: Live Volatility 3 processing for memory-dump parsing and profile mapping.
    *   *Network Forensics*: Deep PCAP protocol inspection and packet flow analyzer.
    *   *Mobile Forensics*: Android/iOS backup file parsing and raw sqlite artifact extractor.


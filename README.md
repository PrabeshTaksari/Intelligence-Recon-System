Intelligence Recon System (IRS)

An AI-assisted reconnaissance and vulnerability intelligence platform. IRS orchestrates industry-standard security tools against a target, correlates their output, and uses AI to turn raw scan data into a readable report — complete with an executive summary, key findings, OWASP Top 10 mapping, severity breakdown, and exportable HTML/PDF reports.

This repository also contains the academic project documentation (proposal, interim report, and final report) alongside the working system.

Overview

Given a target (domain or IP), IRS runs a pipeline of reconnaissance and vulnerability-scanning tools, then feeds the combined output to an AI decision layer that:
  1. Decides which follow-up tools to run based on initial findings (e.g. discovered subdomains feed into further enumeration and exploitation tools)
  2. Summarizes results into an Executive Summary and Key Findings
  3. Maps findings to OWASP Top 10 (2021) categories
  4. Produces a severity distribution and historical scan trend data
  5. Generates a shareable HTML/PDF report
  6. It also supports scheduled recurring scans and email alerts when a scan completes.

Architecture
 1. Backend: FastAPI (Python, async), SQLAlchemy + SQLite (fastapi, uvicorn[standard], python-dotenv, sqlalchemy, aiosqlite, httpx, weasyprint — see                requirements.txt)
 2.Frontend: Static HTML/CSS/JS served directly by the backend
 3. AI layer: Google Gemini (configurable model/backends), used for the decision engine and report generation, with local fallbacks when disabled
 4. Recon/scanning tools: Shelled out to as external CLI binaries (ProjectDiscovery suite and others)
 5. Reporting: WeasyPrint (HTML → PDF)

app/
├── ai/            # AI decision engine, prompts, report generation
├── api/           # FastAPI routers (scans, reports, tools, schedules, settings, health)
├── core/          # Config, database, logging, websocket updates
├── models/        # SQLAlchemy models
├── schemas/       # Pydantic schemas
├── services/      # Scan orchestration, intelligence summary, report building, email alerts
├── tools/         # Wrappers for each recon/scanning tool
└── utils/
Frontend/          # Static single-page UI
data/              # SQLite DB, scan artifacts, alert settings (generated at runtime)
docs/              # Project documentation (pending upload — see note below)
install.sh         # Sets up venv and installs Python dependencies
install-tools.sh   # Installs external recon/scanning tools (Go, pip, gem)
requirements.txt   # Python dependencies
resume.cfg         # Project/resume config


Supported Tools
IRS drives the following tools (must be installed separately and available on PATH):

Category	                                                        Tools
Port/service discovery	                                          Naabu, Httpx
Subdomain enumeration	                                            Subfinder, Amass, Assetfinder, Sublist3r, DNSx, ShuffleDNS
Crawling / URL discovery	                                        GAU, Katana, GoSpider
Fuzzing	                                                          FFuf, Wfuzz
Vulnerability scanning	                                          Nuclei
Wordlist generation	                                              CeWL


Naabu and Httpx run first to gather initial clues; the AI decision layer then chooses which discovery and exploitation tools to chain next based on what was found.
install-tools.sh installs most of these automatically:
 1. Via go install: Httpx, Nuclei, Naabu, DNSx, ShuffleDNS, Katana, GAU, GoSpider, Subfinder, Assetfinder, FFuf, Amass
 2. Via pip (inside the venv): Wfuzz, Sublist3r
 3. Via gem: CeWL

Prerequisites
Tested on Debian/Ubuntu-based Linux. You'll need:
 1. Python 3.10+
 2. Go 1.21+ (for installing the ProjectDiscovery-based recon tools)
 3. Ruby + RubyGems (for CeWL)
 4. Git
 5. A Google Gemini API key (optional — the platform can run with AI features disabled)

If any of these aren't already on your system, install them first:
Update package lists
sudo apt update

# Python, pip, venv, git
sudo apt install -y python3 python3-pip python3-venv git

# Go (for the recon tool installers)
sudo apt install -y golang-go
# If your distro's Go is too old, install manually instead:
#   wget https://go.dev/dl/go1.22.linux-amd64.tar.gz
#   sudo tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz
#   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
#   source ~/.bashrc

# Ruby + RubyGems (for CeWL)
sudo apt install -y ruby-full

# System libraries required by WeasyPrint (PDF report generation)
sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

Installation
 1. Clone the repository
    
   git clone https://github.com/PrabeshTaksari/Intelligence-Recon-System.git
   cd Intelligence-Recon-System
 2. Set up the Python environment install.sh creates a virtual environment and installs everything in requirements.txt, then automatically runs install-tools.sh:
bash
   chmod +x install.sh install-tools.sh
   ./install.sh
 3. Make sure the external recon tools are on your PATH install-tools.sh (run automatically by install.sh) installs:
     -Via go install: Httpx, Nuclei, Naabu, DNSx, ShuffleDNS, Katana, GAU, GoSpider, Subfinder, Assetfinder, FFuf, Amass
     -Via pip (inside the venv): Wfuzz, Sublist3r
     -Via gem: CeWL
Go tools are installed to $(go env GOBIN) or $(go env GOPATH)/bin. Add that to your shell's PATH if it isn't already:

   echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
   source ~/.bashrc

Verify each tool is reachable:

   nuclei -version
   naabu -version
   httpx -version
   subfinder -version
   dnsx -version
   shuffledns -version
   katana -version
   gau --version
   gospider -v
   assetfinder -h
   ffuf -V
   amass -version
   wfuzz --version
   cewl --version

Amass and GAU installs can occasionally fail depending on your Go version — install-tools.sh warns but continues if so. Re-run ./install-tools.sh or install the affected tool manually if needed.

4. Configure environment variables Create a .env file in the project root:

   cat > .env << 'EOF'
   # AI (optional — leave GEMINI_API_KEY blank to disable AI features)
   GEMINI_API_KEY=your_api_key_here
   GEMINI_MODEL=gemini-2.5-flash
   INTELLIGENCE_AI_ENABLED=true

   # Database (defaults to local SQLite if unset)
   DATABASE_URL=sqlite+aiosqlite:///./data/irs.db

   # Tool execution
   TOOL_TIMEOUT=300
   NUCLEI_TIMEOUT=1500
   MAX_CONCURRENT_TOOLS=3

   # Email alerts (optional)
   SMTP_HOST=
   SMTP_PORT=587
   SMTP_USER=
   SMTP_PASSWORD=
   SMTP_FROM=
   SMTP_USE_TLS=true
   EOF
   
5. Activate the virtual environment and run the application

   source venv/bin/activate
   python -m app.main
   # or, for auto-reload during development:
   # FASTAPI_RELOAD=true uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

6. Open http://localhost:8080 in your browser.
Quick reference: full setup from a clean machine

sudo apt update
sudo apt install -y python3 python3-pip python3-venv git golang-go ruby-full \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

git clone https://github.com/PrabeshTaksari/Intelligence-Recon-System.git
cd Intelligence-Recon-System

chmod +x install.sh install-tools.sh
./install.sh

echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

cat > .env << 'EOF'
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash
INTELLIGENCE_AI_ENABLED=true
DATABASE_URL=sqlite+aiosqlite:///./data/irs.db
TOOL_TIMEOUT=300
NUCLEI_TIMEOUT=1500
MAX_CONCURRENT_TOOLS=3
EOF

source venv/bin/activate
python -m app.main

Then visit http://localhost:8080.

Usage
  1. Enter a target domain or IP in the web UI and start a scan.
  2. Watch live progress as Naabu/Httpx gather initial clues, followed by the AI-selected chain of discovery and exploit tools.
  3. Once complete, review the Executive Summary, Key Findings, OWASP Top 10 mapping, and severity breakdown.
  4. Export the report as HTML or PDF, or save it for later reference.
  5. Optionally, configure a scheduled scan to re-run against a target automatically and receive an email alert when it finishes.

API

The backend exposes a REST API under /api, including:

POST /api/scans — start a new scan
GET /api/scans/{scan_id}/status — poll scan status
GET /api/scans/{scan_id}/findings — retrieve findings
GET /api/scans/{scan_id}/intelligence-summary — AI-generated summary
GET /api/{scan_id}/report / GET /api/{scan_id}/report/pdf — HTML/PDF report
GET /api/scans/stats/severity, .../trend — dashboard statistics
GET|POST|PATCH|DELETE /api/scheduled-scans — manage recurring scans
GET /api/health — health check


⚠️ Responsible Use

This tool actively scans and probes network targets, which can trigger intrusion-detection systems, violate terms of service, or be illegal depending on jurisdiction. Only run scans against systems you own or have explicit written authorization to test. The authors take no responsibility for misuse.

Project Documentation

This repository includes the underlying academic project write-ups:

01 Proposal/ — ✅ included
02 Interim Report/ — ✅ included
03 Main Report/ — ⏳ not yet uploaded to this repository
docs/ — ⏳ not yet uploaded to this repository
License

No license file is currently included in this repository. Add one (e.g. MIT, Apache-2.0) if you intend for others to reuse this code.

Author
Prabesh Sundar Taksari

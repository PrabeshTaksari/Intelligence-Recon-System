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

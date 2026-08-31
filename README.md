Intelligence Recon System (IRS)

An AI-assisted reconnaissance and vulnerability intelligence platform. IRS orchestrates industry-standard security tools against a target, correlates their output, and uses AI to turn raw scan data into a readable report — complete with an executive summary, key findings, OWASP Top 10 mapping, severity breakdown, and exportable HTML/PDF reports.

This repository also contains the academic project documentation (proposal, interim report, and final report) alongside the working system.

Overview

Given a target (domain or IP), IRS runs a pipeline of reconnaissance and vulnerability-scanning tools, then feeds the combined output to an AI decision layer that:

Decides which follow-up tools to run based on initial findings (e.g. discovered subdomains feed into further enumeration and exploitation tools)
Summarizes results into an Executive Summary and Key Findings
Maps findings to OWASP Top 10 (2021) categories
Produces a severity distribution and historical scan trend data
Generates a shareable HTML/PDF report

It also supports scheduled recurring scans and email alerts when a scan completes.

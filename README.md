# Automated Web Vulnerability Scanner (Lightweight DAST Framework)

## 1. Project Overview & Objective
This project is an extensible, lightweight Python-based Dynamic Application Security Testing (DAST) scanner. It maps web application attack surfaces, extracts interactive injection points (forms, parameters, endpoints), fuzzes inputs with benign heuristic probes, and detects common OWASP Top 10 vulnerabilities (including SQL Injection, Reflected Cross-Site Scripting, Missing Security Headers, and SSRF).

Headless browser automation via Playwright ensures coverage of modern Single Page Applications (SPAs) and dynamic DOM manipulations alongside traditional static HTML crawling.

---

## 2. Architecture & Workflow

```text
                      [ Target URL / Scope ]
                                │
                                ▼
    ┌──────────────────────────────────────────────────────┐
    │                 1. CRAWLER & SPIDER                  │
    │  - Static HTTP extraction (BeautifulSoup)            │
    │  - Dynamic DOM rendering & AJAX spider (Playwright)  │
    │  - Scope enforcement (Domain & Subpath whitelist)    │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             2. ATTACK SURFACE EXTRACTOR              │
    │  - Discovered URLs with Query Parameters (?p=...)    │
    │  - Form & Input Parsers (GET/POST, action, fields)   │
    │  - HTTP Headers & Cookie Metadata                    │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             3. HEURISTIC FUZZING ENGINE              │
    │  - Modular vulnerability probes (benign heuristics)  │
    │  - Canary injection & response diffing               │
    │  - Error pattern signatures & response timing        │
    └──────────────┬───────────┬───────────┬───────────────┘
                   │           │           │
          ┌────────┴───┐ ┌─────┴─────┐ ┌───┴──────────┐
          │  modules/  │ │ modules/  │ │   modules/   │
          │  sqli.py   │ │  xss.py   │ │  headers.py  │ ...
          └────────────┘ └───────────┘ └──────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │               4. RESPONSE & DOM ANALYZER             │
    │  - RegEx Signature Matching (DBMS error signatures)  │
    │  - Reflection & Context Breakout Verification        │
    │  - Missing Security Headers & Cookie Flags Audit     │
    └──────────────────────────┬───────────────────────────┘
                               │
                               ▼
    ┌──────────────────────────────────────────────────────┐
    │             5. REPORT GENERATION ENGINE              │
    │  - Structured JSON for CI/CD integration             │
    │  - Human-readable Markdown & HTML summaries          │
    │  - Remediation guidance & CVSS scoring breakdown     │
    └──────────────────────────────────────────────────────┘
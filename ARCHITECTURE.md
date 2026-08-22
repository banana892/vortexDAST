> **File location:** Root directory (`./ARCHITECTURE.md`)  
> **Purpose:** Detailed heuristic specs, detection rules, and module implementation logic for coding.



```markdown
# Scanner Technical Specifications & Detection Heuristics

This document details the internal logic and detection rules for each scanning module.

---

## 1. Security Headers & Configuration (`modules/headers_audit.py`)
Evaluates the baseline HTTP response headers from the initial target URL.

* **Audit Targets**:
  * `Strict-Transport-Security` (HSTS)
  * `Content-Security-Policy` (CSP)
  * `X-Frame-Options` (Clickjacking mitigation)
  * `X-Content-Type-Options: nosniff` (MIME-type sniffing mitigation)
  * `Set-Cookie` flags: `HttpOnly`, `Secure`, `SameSite`
* **Pass/Fail Criteria**: Flags missing headers or cookie attributes as low/informational findings.

---

## 2. Reflected Cross-Site Scripting (`modules/xss_check.py`)
Detects unescaped reflection in dynamic endpoints.

* **Execution Steps**:
  1. Generate a unique, harmless alphanumeric canary probe (e.g., `probe_x7a91k< >"'`).
  2. Inject the probe into discovered GET parameters and POST form bodies.
  3. Parse the HTTP response body:
     * Check if boundary tokens (`<`, `>`, `"`, `'`) are returned verbatim without proper HTML entity encoding (`&lt;`, `&gt;`, `&quot;`, `&#39;`).
  4. (Optional Dynamic Mode): Open the URL in headless Chromium via Playwright and verify if injected elements mutate the live DOM tree.

---

## 3. SQL Injection Syntax Checking (`modules/sqli_check.py`)
Detects database syntax errors caused by input boundary disruption.

* **Execution Steps**:
  1. Submit benign boundary characters (`'`, `"`, `')`, `--`) across input parameters.
  2. Perform regex pattern matching on the response body for standard DBMS engine errors:
     * **MySQL / MariaDB**: `You have an error in your SQL syntax`, `Warning: mysql_`
     * **PostgreSQL**: `PostgreSQL query failed: ERROR: parser: parse error`
     * **SQLite**: `SQLite3::SQLException`, `near "[...]": syntax error`
     * **MSSQL**: `Driver][SQL Server]Unclosed quotation mark`
     * **Oracle**: `ORA-00933: SQL command not properly ended`
  3. Diff against baseline responses to eliminate pre-existing 500 error false positives.

---

## 4. Server-Side Request Forgery (`modules/ssrf_check.py`)
Detects insecure backend URL retrieval parameters.

* **Execution Steps**:
  1. Filter discovered query parameters for URL indicators (e.g., `url=`, `dest=`, `redirect=`, `src=`).
  2. Inject safe local loopback targets (e.g., `http://127.0.0.1:80`, `http://[::1]`, `http://localhost`).
  3. Analyze response codes, body differences, or loopback connection errors indicating internal service fetching attempts.

---

## 5. Development Roadmap

| Phase | Component | Tasks |
| :--- | :--- | :--- |
| **Phase 1** | Session & Request Layer | Implement `core/requester.py` with custom user agents, timeouts, and rate limits. |
| **Phase 2** | Discovery Engine | Build `core/crawler.py` and `core/parser.py` using BeautifulSoup and Playwright. |
| **Phase 3** | Passive Auditor | Build `modules/headers_audit.py` to test base response headers. |
| **Phase 4** | Active Fuzzers | Implement `modules/xss_check.py` and `modules/sqli_check.py`. |
| **Phase 5** | Reporter & CLI | Create `core/reporter.py` and finalize `scanner.py` with Rich/Argparse. |
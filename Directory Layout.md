web-vuln-scanner/
│
├── core/
│   ├── __init__.py
│   ├── crawler.py           # Static & dynamic link discoverer, SPA crawler
│   ├── parser.py            # Extracts <form>, <input>, query params, endpoints
│   ├── requester.py         # Session management, custom headers, rate-limiting
│   ├── dom_watcher.py       # Playwright browser manager for JS-rendered apps
│   └── reporter.py          # Formats scan output (JSON/Markdown/HTML)
│
├── modules/
│   ├── __init__.py
│   ├── base.py              # Abstract Base Class (BaseScannerModule)
│   ├── headers_audit.py     # Checks missing HSTS, CSP, X-Frame, X-Content-Type
│   ├── xss_check.py         # Reflected input & canary probe validation
│   ├── sqli_check.py        # Boundary characters & DBMS syntax error analysis
│   └── ssrf_check.py        # Loopback URL parameter checks & protocol anomalies
│
├── payloads/
│   ├── sqli_probes.json     # Non-destructive syntax boundary probes
│   ├── xss_canaries.json    # Safe alphanumeric canary tokens
│   └── ssrf_probes.json     # Benign localhost & loopback test identifiers
│
├── tests/
│   ├── test_crawler.py
│   └── test_modules.py
│
├── config.yaml              # Crawl depth, timeout, rate limits, scope rules
├── scanner.py               # CLI entrypoint (CLI args via argparse/click)
├── requirements.txt         # Dependencies
└── README.md                # Project documentation & execution guide
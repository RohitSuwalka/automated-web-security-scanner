# 🔒 Automated Web Security Scanner

A professional, browser-based web security scanner built with Python and Streamlit.
Analyzes HTTP security headers, TLS/HTTPS certificates, and CORS configuration,
producing a transparent Security Configuration Score and downloadable reports.

> **Built as a cybersecurity bootcamp project — for educational and authorised use only.**

---

## ✨ Features

- **6 HTTP Security Header Checks** — Content-Security-Policy, Strict-Transport-Security,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS / HTTPS Certificate Validation** — expiry, self-signed detection, TLS version
- **CORS Misconfiguration Detection** — wildcard origins, credential leakage, origin reflection
- **SSRF Protection** — blocks private IPs (RFC-1918), loopback, link-local, `.local`/`.internal` domains
- **Transparent Scoring** — 0–100 Security Configuration Score with grade (A+ to F) and per-check breakdown
- **Downloadable Reports** — JSON and self-contained HTML reports
- **Professional Dashboard** — dark cybersecurity theme, severity cards, findings explorer
- **Authorization Gate** — requires user to confirm scan authorization before running

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/web-security-scanner.git
cd web-security-scanner

# Install dependencies
pip install -r requirements.txt
```

### Run the App

```bash
streamlit run app.py
```

The browser will open automatically at `http://localhost:8501`.

### Run Tests

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## 🏗️ Project Structure

```
web-security-scanner/
├── app.py              ← Entire application (single-file architecture)
│   ├── Section 1: Imports & Constants (Finding TypedDict, CHECK_WEIGHTS)
│   ├── Section 2: SSRF Guard & URL Validator
│   ├── Section 3: HTTP Security Header Scanner
│   ├── Section 4: TLS / HTTPS Certificate Scanner
│   ├── Section 5: CORS Scanner
│   ├── Section 6: Scoring Engine
│   ├── Section 7: Report Generators (JSON + HTML)
│   └── Section 8: Streamlit Dashboard
├── requirements.txt
├── README.md
├── LICENSE
└── tests/
    ├── conftest.py     ← Shared fixtures
    └── test_app.py     ← 42 pytest tests
```

---

## 📊 Scoring Methodology

The **Security Configuration Score** (0–100) reflects the presence and basic configuration
of security controls — it is **not a guarantee of security**.

| Check | Check ID | Max Points | PASS | WARN | FAIL |
|-------|----------|-----------|------|------|------|
| Content-Security-Policy | `csp` | 20 | 20 | 10 | 0 |
| Strict-Transport-Security | `hsts` | 15 | 15 | 7 | 0 |
| X-Frame-Options | `xfo` | 10 | 10 | 5 | 0 |
| X-Content-Type-Options | `xcto` | 10 | 10 | 0 | 0 |
| Referrer-Policy | `rp` | 10 | 10 | 5 | 0 |
| Permissions-Policy | `pp` | 5 | 5 | 2 | 0 |
| TLS Certificate | `tls` | 15 | 15 | 7 | 0 |
| CORS Configuration | `cors` | 15 | 15 | 7 | 0 |
| **Total** | | **100** | | | |

**Grade thresholds:** A+ ≥ 90 · A ≥ 80 · B ≥ 70 · C ≥ 60 · D ≥ 50 · F < 50

**Formula:** `score = round((earned_points / 100) * 100)` where `pass = max_points`, `warn = max_points // 2`, `fail = 0`. Missing/inconclusive checks count as `warn`.

---

## 🛡️ Security & SSRF Protection

The scanner includes multiple layers to prevent misuse:

- **Scheme enforcement** — only `http://` and `https://` URLs are accepted
- **Private IP denylist** — blocks RFC-1918 (10.x, 172.16-31.x, 192.168.x), loopback (127.x, ::1), and link-local (169.254.x) ranges
- **Hostname denylist** — blocks `localhost`, `.local`, and `.internal` destinations
- **DNS resolution check** — resolves hostnames and validates resolved IPs before connecting
- **Allowlist mode** — optional UI toggle to restrict scanning to pre-approved hostnames
- **Authorization gate** — user must confirm they have permission to scan before the button activates

---

## ⚠️ Limitations & Disclaimer

This tool performs **surface-level, passive scanning** based on HTTP responses:

- Results reflect the **state at scan time** — not a continuous or comprehensive security assessment
- **False positives are possible** — some headers may be set by CDNs, proxies, or load balancers not visible in a single GET request
- **False negatives are possible** — a high score does not mean the target is secure; many critical vulnerabilities (SQLi, XSS, auth flaws) are outside this tool's scope
- TLS checks require a live HTTPS connection — firewalls or WAFs may affect results
- CORS checks use a passive probe approach — some CORS misconfigurations may not be detected
- **Always obtain explicit written authorization before scanning any target you do not own**

---

## 🔧 Configuration

No configuration files are required. All settings are adjustable through the Streamlit sidebar:

- **Allowlist mode** — restrict scanning to specific hostnames
- Scan timeout defaults to **10 seconds** per check module

---

## 🧪 Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test class
pytest tests/test_app.py::TestValidator -v
pytest tests/test_app.py::TestHeaderScanner -v
pytest tests/test_app.py::TestTLSScanner -v
pytest tests/test_app.py::TestCORSScanner -v
pytest tests/test_app.py::TestScoring -v
pytest tests/test_app.py::TestReports -v

# With coverage report
pytest tests/ --cov=app --cov-report=term-missing
```

---

## 📄 Report Formats

### JSON Report
Structured machine-readable output including scan metadata, score, severity counts, per-check breakdown, and full findings array.

### HTML Report
Self-contained HTML file (inline CSS, no external dependencies) with:
- Score badge and grade
- Severity summary cards
- Score breakdown table
- Full findings table
- Detailed findings with description, evidence, and recommendations
- Disclaimer footer

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes and add tests
4. Run `pytest tests/ -v` — all tests must pass
5. Submit a pull request

---

## 📜 Licence

MIT Licence — see [LICENSE](LICENSE) for details.

---

## 🎓 About This Project

Built as a cybersecurity bootcamp capstone project demonstrating:
- Python security engineering best practices
- SSRF protection and input validation
- HTTP security header analysis
- TLS certificate parsing with the `cryptography` library
- Streamlit dashboard development
- pytest-based test-driven development
- Professional project structure and documentation

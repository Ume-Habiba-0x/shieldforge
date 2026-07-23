
# ShieldForge

Modular Web Security Testing Framework

**Version:** 1.0.0  
**Python:** 3.10+  
**License:** Educational

## Overview

ShieldForge is a command-line framework for automated web application security testing. It provides five independent scanning modules that share a common execution engine, HTTP client, and reporting system. The framework is designed to test against intentionally vulnerable web applications.

---

## Architecture

ShieldForge follows a modular architecture.

- `framework.py` parses CLI arguments and starts the scan.
- The execution engine initializes a shared scan context.
- Selected scanner modules execute independently.
- All modules share the same HTTP client, logger, and reporting system.
- Results are aggregated and exported as text, HTML, or JSON.

---

## Features

- CLI interface with module selection
- HTML and JSON report generation
- Colored terminal output
- Configurable timeout and User-Agent

### Scanner Modules

| Module | Function | Status |
|--------|----------|--------|
| Headers | Analyze HTTP security headers | Stable |
| Auth | Assess login mechanisms and session cookies | Stable |
| XSS | Detect reflected XSS in GET parameters | Stable |
| SQLi | Detect SQL injection (error, boolean, time-based) | Stable |
| Disclosure | Identify exposed resources and files | Stable |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| HTTP Client | requests |
| HTML Parsing | BeautifulSoup4 |
| XML Parser | lxml |
| Testing | pytest |
| CLI | argparse |
| Logging | loguru |

---

## Project Structure

```
shieldforge/
├── config/
│   └── payloads/
│       ├── sqli_payloads.txt
│       └── xss_payloads.txt
├── core/
│   ├── context.py
│   ├── engine.py
│   └── models.py
├── modules/
│   ├── base.py
│   ├── headers.py
│   ├── auth.py
│   ├── xss.py
│   ├── sqli.py
│   └── disclosure.py
├── reports/
│   ├── base.py
│   ├── html_generator.py
│   └── json_generator.py
├── tests/
│   ├── test_scanners/
│   │   ├── test_headers.py
│   │   ├── test_auth.py
│   │   ├── test_xss.py
│   │   ├── test_sqli.py
│   │   └── test_disclosure.py
│   └── test_reports/
├── utils/
│   ├── http_client.py
│   ├── logger.py
│   └── validators.py
├── framework.py
├── requirements.txt
└── README.md
```

| Directory | Purpose |
|-----------|---------|
| `core/` | Execution engine and shared models |
| `modules/` | Security scanners |
| `reports/` | Report generation (HTML, JSON) |
| `utils/` | HTTP client, logging, validation |
| `tests/` | Unit tests |
| `config/` | Payloads and configuration |

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/Ume-Habiba-0x/shieldforge.git
cd shieldforge

# Create and activate virtual environment (recommended)
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Tested On

- Linux
- Windows
- Python 3.10+

---

## Usage

### CLI Help

```bash
python framework.py --help
```

### Command Syntax

```bash
python framework.py --target <TARGET_URL> --module <MODULE_NAME> [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `--target` | Target URL to scan |

### Module Selection

| Argument | Description |
|----------|-------------|
| `--module` | Comma-separated module names (e.g., `headers,sqli`) or `all` |

### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--output` | Output format: `text`, `html`, `json` | `text` |
| `--timeout` | Request timeout in seconds | `30` |
| `--user-agent` | Custom User-Agent | `ShieldForge/1.0` |

### Examples

```bash
# Single module
python framework.py --target http://testphp.vulnweb.com --module headers

# Multiple modules
python framework.py --target http://testphp.vulnweb.com --module headers,sqli

# All modules
python framework.py --target http://192.168.108.130/dvwa/login.php --module all

# HTML report
python framework.py --target http://testphp.vulnweb.com --module headers --output html

# JSON report
python framework.py --target http://testphp.vulnweb.com --module headers --output json

# Custom timeout and User-Agent
python framework.py --target http://testphp.vulnweb.com --module headers --timeout 60 --user-agent "CustomAgent/1.0"
```

### Example Output

```
[INFO] Running Headers Scanner...

HIGH
Missing Content-Security-Policy

MEDIUM
Missing X-Frame-Options

LOW
Server header disclosed
```

### Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Scan completed successfully |
| 1 | Invalid arguments |
| 2 | Target unreachable |
| 3 | Internal framework error |

### Reports

Generated reports are saved in the current directory.

```
reports/
├── shieldforge_report.html
└── shieldforge_report.json
```

---

## Module Details

### Headers Scanner

Analyzes HTTP security headers.

**Headers checked:**
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Strict-Transport-Security
- Permissions-Policy

**Output:** Existing headers, missing headers, severity rating, recommendations

### Authentication Scanner

Evaluates login functionality and session security.

**Checks performed:**
- Session cookie security flags (Secure, HttpOnly, SameSite)
- Password policy indicators
- Login response differences

**Output:** Cookie security findings, password policy observations

### XSS Scanner

Tests GET parameters for reflected XSS.

**Requirements:**
- GET parameters only
- Safe payloads from `config/payloads/xss_payloads.txt`
- Payload encoding
- Detection based on reflected responses

**Output:** Reflected XSS findings with payload evidence

### SQL Injection Scanner

Performs safe SQL injection detection.

**Techniques:**
- Error-based: syntax-breaking payloads, DB error signature matching
- Boolean-based: true/false payload pairs, response comparison
- Time-based: delay payloads with zero-delay control

**Safety:** No destructive payloads. No DROP/DELETE/UPDATE/INSERT statements.

**Output:** SQL injection findings with detection technique and confidence score

### Information Disclosure Scanner

Detects exposed resources.

**Resources checked:**
- robots.txt
- sitemap.xml
- .git directory
- Backup files
- phpinfo
- Directory listing
- Configuration files

**Output:** Exposed resource findings

---

## Reports

### HTML Report

Generated with `--output html`. Saved as `shieldforge_report.html` in the current directory.

Contains:
- Target URL and scan date
- Modules executed
- Findings organized by module
- Severity color coding
- Evidence and remediation suggestions
- Overall risk summary

### JSON Report

Generated with `--output json`. Saved as `shieldforge_report.json` in the current directory.

Contains structured JSON with:
- Scan metadata
- All findings with severity, evidence, and remediation
- Severity breakdown

---

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific module tests
pytest tests/test_scanners/test_headers.py
pytest tests/test_scanners/test_sqli.py

# Run with verbose output
pytest tests/ -v
```

### Test Structure

```
tests/
├── test_scanners/
│   ├── test_headers.py
│   ├── test_auth.py
│   ├── test_xss.py
│   ├── test_sqli.py
│   └── test_disclosure.py
└── test_reports/
    ├── test_html.py
    └── test_json.py
```

---

## Development

### Adding a New Module

1. Create a new file in `modules/`
2. Subclass `BaseScanner`
3. Implement required properties: `name`, `description`
4. Implement `scan(self, context: Context) -> ScanResult` method
5. Use `context.http_client` for HTTP requests
6. Use `context.logger` for logging
7. Return findings as `Finding` objects

### Module Template

```python
from modules.base import BaseScanner
from core.context import Context
from core.models import ScanResult, Finding, Severity

class NewScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "new_scanner"

    @property
    def description(self) -> str:
        return "Description of what this scanner does"

    def scan(self, context: Context) -> ScanResult:
        findings = []
        # Detection logic here
        if vulnerability_found:
            findings.append(Finding(
                module=self.name,
                category="category",
                title="Finding title",
                description="Detailed description",
                severity=Severity.HIGH,
                evidence={"key": "value"},
                remediation="How to fix"
            ))
        return self._create_result(findings=findings, target=context.config.target_url)
```

---

## Roadmap

- Authentication session support
- POST parameter XSS testing
- Concurrent scanning
- YAML configuration
- Plugin system
- Progress indicator

---

## Known Limitations

| Limitation | Description |
|------------|-------------|
| Cookie/Session support | Not implemented; authenticated targets may require manual login |
| Multi-threading | Not implemented |
| POST parameters | XSS module only tests GET parameters |
| Configuration file | Not implemented; command line only |
| Progress bar | Not implemented |

---

## Security Considerations

- All SQL injection payloads are non-destructive
- XSS payloads are safe (no malicious code execution)
- No data modification operations performed
- Only tests for vulnerability indicators, does not exploit

---

## Contributing

### Branch Strategy

- `main` - Production-ready code
- `feature/*` - New features
- `fix/*` - Bug fixes

### Commit Messages

Format: `<type>(<scope>): <subject>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Pull Request Process

1. Create feature branch from `main`
2. Implement changes with tests
3. Open pull request
4. Code review required
5. Merge after approval

---

## License

Educational and research purposes only.

---

## Disclaimer

ShieldForge is intended exclusively for security testing of systems that you own or have explicit authorization to assess. Unauthorized use against third-party systems is prohibited.

Recommended practice targets:
- DVWA
- OWASP Juice Shop
- bWAPP
- WebGoat
- Mutillidae
```

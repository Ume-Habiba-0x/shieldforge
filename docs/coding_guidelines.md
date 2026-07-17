Coding Guidelines
Style
Type hints on all public methods
Google-style docstrings
No print() — use logger from utils.logger

Imports
# Good
from core.context import Context
from core.models import Finding, Severity, ScanResult
from modules.base import BaseScanner

# Bad
import requests  # Use context.http_client instead



Error Handling

def scan(self, context: Context) -> ScanResult:
    findings = []
    errors = []
    try:
        response = context.http_client.get(target)
    except Exception as e:
        errors.append(f"Failed: {str(e)}")
        logger.error("Scan failed: %s", e)
    return self._create_result(findings=findings, errors=errors, target=target)




Commits
Format: type(scope): description
feat(xss): add reflected XSS detection
fix(engine): handle timeout error
test(headers): add CSP parsing tests

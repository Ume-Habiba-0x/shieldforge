"""ShieldForge — Security Headers Analyzer."""

import logging
from typing import List

from core.context import Context
from core.models import Finding, Severity, ScanResult
from modules.base import BaseScanner

logger = logging.getLogger(__name__)


class HeadersScanner(BaseScanner):
    """Analyze HTTP security headers."""

    SECURITY_HEADERS = {
        "Content-Security-Policy": (True, "Define CSP to prevent XSS", Severity.HIGH),
        "X-Frame-Options": (True, "Set to DENY or SAMEORIGIN", Severity.MEDIUM),
        "X-Content-Type-Options": (True, "Set to nosniff", Severity.MEDIUM),
        "Referrer-Policy": (False, "Set strict policy", Severity.LOW),
        "Strict-Transport-Security": (True, "Set HSTS max-age >= 31536000", Severity.HIGH),
        "Permissions-Policy": (False, "Restrict browser features", Severity.LOW),
    }

    @property
    def name(self) -> str:
        return "headers"

    @property
    def description(self) -> str:
        return "Analyze HTTP security headers"

    def scan(self, context: Context) -> ScanResult:
        target = context.config.target_url
        findings: List[Finding] = []
        errors: List[str] = []

        try:
            response = context.http_client.head(target)
            headers = response.headers

            for header_name, (required, recommendation, severity) in self.SECURITY_HEADERS.items():
                header_value = headers.get(header_name)

                if header_value is None:
                    findings.append(Finding(
                        module=self.name,
                        category="missing_header",
                        title=f"Missing {header_name}",
                        description=f"The {header_name} header is not set.",
                        severity=severity if required else Severity.INFO,
                        evidence={"header_name": header_name, "present": False},
                        remediation=recommendation,
                        confidence=1.0
                    ))
                else:
                    misconfig = self._check_misconfiguration(header_name, header_value)
                    if misconfig:
                        findings.append(misconfig)

            server = headers.get("Server")
            if server:
                findings.append(Finding(
                    module=self.name,
                    category="information_disclosure",
                    title="Server Header Disclosure",
                    description=f"Server reveals: {server}",
                    severity=Severity.LOW,
                    evidence={"header": "Server", "value": server},
                    remediation="Remove or obfuscate Server header",
                    confidence=1.0
                ))

        except Exception as e:
            errors.append(f"Failed: {str(e)}")
            logger.error("Headers scan failed: %s", e)

        return self._create_result(findings=findings, errors=errors, target=target)

    def _check_misconfiguration(self, header_name: str, value: str):
        value_lower = value.lower()

        if header_name == "X-Frame-Options":
            if value_lower not in ["deny", "sameorigin"]:
                return Finding(
                    module=self.name,
                    category="misconfigured_header",
                    title=f"Weak {header_name}",
                    description=f"X-Frame-Options is '{value}'",
                    severity=Severity.MEDIUM,
                    evidence={"header": header_name, "value": value},
                    remediation="Set to DENY or SAMEORIGIN",
                    confidence=0.9
                )

        if header_name == "Strict-Transport-Security":
            if "max-age" not in value_lower:
                return Finding(
                    module=self.name,
                    category="misconfigured_header",
                    title=f"Incomplete {header_name}",
                    description="HSTS missing max-age",
                    severity=Severity.MEDIUM,
                    evidence={"header": header_name, "value": value},
                    remediation="Add max-age=31536000",
                    confidence=0.9
                )

        if header_name == "Content-Security-Policy":
            if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
                return Finding(
                    module=self.name,
                    category="weak_csp",
                    title="CSP Allows Unsafe Scripts",
                    description="CSP contains unsafe directives",
                    severity=Severity.MEDIUM,
                    evidence={"header": header_name, "value": value},
                    remediation="Remove unsafe-inline and unsafe-eval",
                    confidence=0.8
                )

        return None

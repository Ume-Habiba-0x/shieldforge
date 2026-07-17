"""ShieldForge — Shared data models.

All modules use these models to communicate findings.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding/vulnerability."""
    module: str
    category: str
    title: str
    description: str
    severity: Severity
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Output from a single scanner module."""
    module_name: str
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    duration_ms: int = 0
    target: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "target": self.target,
        }

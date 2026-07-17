"""ShieldForge — Shared context (the backpack)."""

from dataclasses import dataclass, field
from typing import Optional

from core.models import Finding, ScanResult, Severity


@dataclass
class Config:
    """ShieldForge configuration."""
    target_url: str = ""
    modules: list = field(default_factory=list)
    output_format: str = "text"
    timeout: int = 10
    proxy: Optional[str] = None
    user_agent: str = "ShieldForge/1.0"
    verify_ssl: bool = True


@dataclass
class Context:
    """Shared state across all ShieldForge modules."""
    config: Config = field(default_factory=Config)
    scan_results: list = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add_result(self, result: ScanResult) -> None:
        self.scan_results.append(result)

    def get_all_findings(self) -> list[Finding]:
        findings = []
        for result in self.scan_results:
            findings.extend(result.findings)
        return findings

    def get_summary(self) -> dict:
        all_findings = self.get_all_findings()
        severity_counts = {s.value: 0 for s in Severity}
        for f in all_findings:
            severity_counts[f.severity.value] += 1

        return {
            "target": self.config.target_url,
            "modules_run": len(self.scan_results),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
        }

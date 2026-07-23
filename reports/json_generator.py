"""ShieldForge -- JSON report generator."""

import json
from datetime import datetime

from core.context import Context
from reports.base import BaseReport

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class JSONReport(BaseReport):
    @property
    def format_name(self) -> str:
        return "json"

    def generate(self, context: Context) -> str:
        summary = context.get_summary()

        data = {
            "framework": "ShieldForge",
            "version": "1.0.0",
            "scan_info": {
                "target": context.config.target_url,
                "timestamp": datetime.now().isoformat(),
                "modules": [r.module_name for r in context.scan_results],
            },
            "summary": summary,
            "overall_risk_rating": self._overall_risk_rating(summary["severity_breakdown"]),
            "results": [r.to_dict() for r in context.scan_results],
            "all_findings": [f.to_dict() for f in context.get_all_findings()],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def _overall_risk_rating(severity_breakdown: dict) -> str:
        for level in RISK_ORDER:
            if severity_breakdown.get(level, 0) > 0:
                return level
        return "INFO"

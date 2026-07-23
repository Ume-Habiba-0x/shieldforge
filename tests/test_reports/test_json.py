"""Tests for the JSON report generator."""

import json

from core.context import Config, Context
from core.models import Finding, ScanResult, Severity
from reports.json_generator import JSONReport


def make_context_with_findings():
    context = Context(config=Config(target_url="http://example.test/"))
    finding = Finding(
        module="headers", category="missing_header", title="Missing CSP",
        description="No CSP set", severity=Severity.HIGH,
        evidence={"header": "CSP"}, remediation="Add a CSP header", confidence=1.0,
    )
    context.add_result(ScanResult(module_name="headers", findings=[finding], target=context.config.target_url))
    return context


def test_generate_returns_valid_json_with_target():
    report = JSONReport().generate(make_context_with_findings())
    data = json.loads(report)
    assert data["scan_info"]["target"] == "http://example.test/"


def test_overall_risk_rating_reflects_highest_severity():
    report = JSONReport().generate(make_context_with_findings())
    data = json.loads(report)
    assert data["overall_risk_rating"] == "HIGH"


def test_no_findings_gives_info_risk_rating():
    context = Context(config=Config(target_url="http://example.test/"))
    report = JSONReport().generate(context)
    data = json.loads(report)
    assert data["overall_risk_rating"] == "INFO"

"""Tests for the HTML report generator."""

from core.context import Config, Context
from core.models import Finding, ScanResult, Severity
from reports.html_generator import HTMLReport


def make_context_with_findings():
    context = Context(config=Config(target_url="http://example.test/"))

    xss_finding = Finding(
        module="headers", category="missing_header", title="Missing CSP",
        description="<script>alert(1)</script> no CSP set", severity=Severity.HIGH,
        evidence={"header": "<b>CSP</b>"}, remediation="Add a CSP header", confidence=1.0,
    )
    cookie_finding = Finding(
        module="auth", category="session_cookie", title="Cookie missing Secure",
        description="Session cookie lacks Secure flag", severity=Severity.MEDIUM,
        evidence={"cookie": "session"}, remediation="Set Secure flag", confidence=0.9,
    )

    context.add_result(ScanResult(module_name="headers", findings=[xss_finding], target=context.config.target_url))
    context.add_result(ScanResult(
        module_name="auth", findings=[cookie_finding],
        errors=["probe timed out"], target=context.config.target_url,
    ))
    return context


def test_generate_returns_html_document():
    report = HTMLReport().generate(make_context_with_findings())
    assert report.startswith("<!DOCTYPE html>")
    assert "ShieldForge" in report


def test_findings_are_html_escaped():
    report = HTMLReport().generate(make_context_with_findings())
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report


def test_module_errors_are_shown():
    report = HTMLReport().generate(make_context_with_findings())
    assert "probe timed out" in report


def test_overall_risk_rating_reflects_highest_severity():
    report = HTMLReport().generate(make_context_with_findings())
    assert "HIGH RISK" in report


def test_empty_context_shows_no_modules_message():
    context = Context(config=Config(target_url="http://example.test/"))
    report = HTMLReport().generate(context)
    assert "no-findings" in report

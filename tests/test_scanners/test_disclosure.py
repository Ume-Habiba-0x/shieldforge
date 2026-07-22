"""Tests for Disclosure Scanner."""

import pytest
from unittest.mock import Mock, patch

from core.context import Context, Config
from core.models import Severity
from modules.disclosure import DisclosureScanner


def _resp(status_code=404, text=""):
    r = Mock()
    r.status_code = status_code
    r.text = text
    return r


def _context_with_client():
    """Context is a plain dataclass; http_client is only attached by
    Engine at runtime, so tests must attach a mock client themselves."""
    context = Context(config=Config(target_url="https://example.com"))
    context.http_client = Mock()
    return context


class TestDisclosureScanner:
    def test_no_exposures_on_clean_target(self):
        """Every request 404s -> no findings, no errors."""
        scanner = DisclosureScanner()
        context = _context_with_client()
        context.http_client.get.return_value = _resp(404, "Not Found")

        result = scanner.scan(context)

        assert not result.has_findings
        assert result.errors == []

    def test_detects_exposed_env_file(self):
        """A 200 on a known-sensitive path (differing from baseline) is flagged."""
        scanner = DisclosureScanner()
        context = _context_with_client()

        baseline_resp = _resp(404, "Not Found")
        env_resp = _resp(200, "DB_PASSWORD=supersecret\nAPI_KEY=abc123")

        def fake_get(url, **kwargs):
            if url.endswith("/.env"):
                return env_resp
            return baseline_resp

        context.http_client.get.side_effect = fake_get
        result = scanner.scan(context)

        assert result.has_findings
        env_findings = [f for f in result.findings if f.evidence.get("path") == ".env"]
        assert len(env_findings) == 1
        assert env_findings[0].severity == Severity.CRITICAL

    def test_soft_404_is_not_flagged(self):
        """A server that returns 200 with a generic error page for every
        path (soft-404) must not be reported as exposing every file."""
        scanner = DisclosureScanner()
        context = _context_with_client()

        soft_404_page = "<html><body>Page not found</body></html>"
        context.http_client.get.return_value = _resp(200, soft_404_page)

        result = scanner.scan(context)

        assert not result.has_findings

    def test_robots_txt_flags_sensitive_disallow_entries(self):
        scanner = DisclosureScanner()
        context = _context_with_client()

        robots_body = "User-agent: *\nDisallow: /admin\nDisallow: /public\nDisallow: /backup/\n"

        def fake_get(url, **kwargs):
            if url.endswith("/robots.txt"):
                return _resp(200, robots_body)
            return _resp(404, "Not Found")

        context.http_client.get.side_effect = fake_get
        result = scanner.scan(context)

        robots_findings = [f for f in result.findings if "robots.txt" in f.title]
        assert len(robots_findings) == 1
        assert "/admin" in robots_findings[0].evidence["flagged_paths"]
        assert "/backup/" in robots_findings[0].evidence["flagged_paths"]
        assert "/public" not in robots_findings[0].evidence["flagged_paths"]

    def test_connection_error_is_reported_not_raised(self):
        scanner = DisclosureScanner()
        context = _context_with_client()
        context.http_client.get.side_effect = Exception("connection refused")

        result = scanner.scan(context)

        assert len(result.errors) >= 1
        assert not result.has_findings

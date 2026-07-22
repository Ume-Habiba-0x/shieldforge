"""Tests for Headers Scanner."""

import pytest
from unittest.mock import Mock

from core.context import Context, Config
from core.models import Severity
from modules.headers import HeadersScanner


def _context_with_client():
    """Context is a plain dataclass; http_client is only attached by
    Engine at runtime, so tests must attach a mock client themselves."""
    context = Context(config=Config(target_url="https://example.com"))
    context.http_client = Mock()
    return context


class TestHeadersScanner:
    def test_missing_all_headers(self):
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200

        scanner = HeadersScanner()
        context = _context_with_client()
        context.http_client.head.return_value = mock_response

        result = scanner.scan(context)

        assert result.has_findings
        csp = [f for f in result.findings if "Content-Security-Policy" in f.title]
        assert len(csp) == 1
        assert csp[0].severity == Severity.HIGH

    def test_connection_error(self):
        scanner = HeadersScanner()
        context = _context_with_client()
        context.http_client.head.side_effect = Exception("fail")

        result = scanner.scan(context)

        assert len(result.errors) == 1

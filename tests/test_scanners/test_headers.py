"""Tests for Headers Scanner."""

import pytest
from unittest.mock import Mock, patch

from core.context import Context, Config
from core.models import Severity
from modules.headers import HeadersScanner


class TestHeadersScanner:
    def test_missing_all_headers(self):
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200
        
        scanner = HeadersScanner()
        context = Context(config=Config(target_url="https://example.com"))
        
        with patch.object(context.http_client, 'head', return_value=mock_response):
            result = scanner.scan(context)
        
        assert result.has_findings
        csp = [f for f in result.findings if "Content-Security-Policy" in f.title]
        assert len(csp) == 1
        assert csp[0].severity == Severity.HIGH

    def test_connection_error(self):
        scanner = HeadersScanner()
        context = Context(config=Config(target_url="https://example.com"))
        
        with patch.object(context.http_client, 'head', side_effect=Exception("fail")):
            result = scanner.scan(context)
        
        assert len(result.errors) == 1

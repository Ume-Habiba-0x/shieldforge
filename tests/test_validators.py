import pytest

from utils.validators import (
    build_url,
    extract_base_url,
    extract_domain,
    extract_query_params,
    has_query_params,
    is_same_origin,
    is_valid_domain,
    is_valid_url,
    sanitize_url,
    validate_url,
)


class TestValidateUrl:
    def test_valid_http_url(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_valid_https_url(self):
        assert validate_url("https://example.com") is not None

    def test_adds_http_scheme_when_missing(self):
        result = validate_url("example.com")
        assert result is not None
        assert result.startswith("http://")

    def test_rejects_empty_string(self):
        assert validate_url("") is None

    def test_rejects_none(self):
        assert validate_url(None) is None

    def test_rejects_localhost(self):
        assert validate_url("http://localhost") is None

    def test_rejects_loopback_ip(self):
        assert validate_url("http://127.0.0.1") is None

    def test_rejects_private_ip(self):
        assert validate_url("http://192.168.1.1") is None

    def test_rejects_ftp_scheme(self):
        assert validate_url("ftp://example.com") is None

    def test_strips_trailing_slash(self):
        assert validate_url("http://example.com/") == "http://example.com"

    def test_lowercases_scheme_and_host(self):
        result = validate_url("HTTP://EXAMPLE.COM")
        assert result is not None
        assert result == result.lower()


class TestIsValidUrl:
    def test_returns_true_for_valid(self):
        assert is_valid_url("http://example.com") is True

    def test_returns_false_for_invalid(self):
        assert is_valid_url("not-a-url") is False

    def test_returns_false_for_localhost(self):
        assert is_valid_url("http://localhost:8080") is False


class TestSanitizeUrl:
    def test_removes_query_string(self):
        assert sanitize_url("http://example.com/page?id=1") == "http://example.com/page"

    def test_removes_fragment(self):
        assert sanitize_url("http://example.com/page#section") == "http://example.com/page"

    def test_removes_both(self):
        assert sanitize_url("http://example.com/page?id=1#top") == "http://example.com/page"

    def test_plain_url_unchanged(self):
        assert sanitize_url("http://example.com/robots.txt") == "http://example.com/robots.txt"


class TestExtractBaseUrl:
    def test_strips_path(self):
        assert extract_base_url("https://example.com/admin/login") == "https://example.com"

    def test_preserves_port(self):
        assert extract_base_url("http://example.com:8080/path") == "http://example.com:8080"

    def test_strips_query(self):
        assert extract_base_url("https://example.com/page?id=1") == "https://example.com"


class TestIsSameOrigin:
    def test_same_origin_different_paths(self):
        assert is_same_origin("http://example.com/a", "http://example.com/b") is True

    def test_different_scheme(self):
        assert is_same_origin("http://example.com", "https://example.com") is False

    def test_different_host(self):
        assert is_same_origin("http://example.com", "http://other.com") is False

    def test_different_port(self):
        assert is_same_origin("http://example.com:80", "http://example.com:8080") is False


class TestExtractDomain:
    def test_simple_domain(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_subdomain(self):
        assert extract_domain("https://sub.example.com") == "sub.example.com"

    def test_empty_string(self):
        assert extract_domain("") == ""


class TestBuildUrl:
    def test_joins_base_and_path(self):
        assert build_url("https://example.com", "/robots.txt") == "https://example.com/robots.txt"

    def test_adds_leading_slash_to_path(self):
        assert build_url("https://example.com", "robots.txt") == "https://example.com/robots.txt"

    def test_strips_trailing_slash_from_base(self):
        assert build_url("https://example.com/", "/robots.txt") == "https://example.com/robots.txt"


class TestHasQueryParams:
    def test_url_with_params(self):
        assert has_query_params("http://example.com/page?id=1") is True

    def test_url_without_params(self):
        assert has_query_params("http://example.com/page") is False

    def test_empty_query_string(self):
        assert has_query_params("http://example.com/page?") is False


class TestExtractQueryParams:
    def test_single_param(self):
        assert extract_query_params("http://example.com/page?id=1") == {"id": "1"}

    def test_multiple_params(self):
        result = extract_query_params("http://example.com/page?id=1&name=test")
        assert "id" in result
        assert "name" in result

    def test_no_params_returns_empty_dict(self):
        assert extract_query_params("http://example.com/page") == {}


class TestIsValidDomain:
    def test_valid_domain(self):
        assert is_valid_domain("example.com") is True

    def test_valid_subdomain(self):
        assert is_valid_domain("sub.example.com") is True

    def test_invalid_spaces(self):
        assert is_valid_domain("not a domain") is False

    def test_single_label(self):
        assert is_valid_domain("localhost") is False

    def test_empty_string(self):
        assert is_valid_domain("") is False
import pytest
from unittest.mock import MagicMock, patch
from requests.exceptions import ReadTimeout, SSLError, ConnectionError

from utils.http_client import HTTPClient, HTTPClientError


@pytest.fixture
def client():
    return HTTPClient(timeout=5, verify_ssl=False)


@pytest.fixture
def mock_response():
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Content-Type": "text/html"}
    response.text = "<html>OK</html>"
    return response


class TestHTTPClientInit:
    def test_default_user_agent_is_set(self, client):
        assert "ShieldForge" in client.session.headers["User-Agent"]

    def test_custom_user_agent(self):
        c = HTTPClient(user_agent="TestAgent/2.0")
        assert c.session.headers["User-Agent"] == "TestAgent/2.0"

    def test_proxy_dict_built_correctly(self):
        c = HTTPClient(proxy="http://127.0.0.1:8080")
        assert c._proxies["http"] == "http://127.0.0.1:8080"
        assert c._proxies["https"] == "http://127.0.0.1:8080"

    def test_no_proxy_returns_none(self):
        c = HTTPClient(proxy=None)
        assert c._proxies is None

    def test_cookies_loaded_into_session(self):
        c = HTTPClient(cookies={"session": "abc123"})
        assert c.session.cookies.get("session") == "abc123"

    def test_extra_headers_merged(self):
        c = HTTPClient(extra_headers={"X-Custom": "value"})
        assert c.session.headers.get("X-Custom") == "value"


class TestHTTPClientGet:
    def test_get_success(self, client, mock_response):
        with patch.object(client.session, "request", return_value=mock_response):
            response = client.get("http://example.com")
        assert response.status_code == 200

    def test_get_timeout_raises_client_error(self, client):
        with patch.object(client.session, "request", side_effect=ReadTimeout()):
            with pytest.raises(HTTPClientError, match="timed out"):
                client.get("http://example.com")

    def test_get_connection_error_raises_client_error(self, client):
        with patch.object(client.session, "request", side_effect=ConnectionError("refused")):
            with pytest.raises(HTTPClientError, match="Connection failed"):
                client.get("http://example.com")

    def test_get_ssl_error_raises_client_error(self, client):
        with patch.object(client.session, "request", side_effect=SSLError("cert verify failed")):
            with pytest.raises(HTTPClientError, match="SSL"):
                client.get("http://example.com")


class TestHTTPClientPost:
    def test_post_success_with_data(self, client, mock_response):
        with patch.object(client.session, "request", return_value=mock_response):
            response = client.post("http://example.com/login", data={"u": "admin"})
        assert response.status_code == 200

    def test_post_success_with_json(self, client, mock_response):
        with patch.object(client.session, "request", return_value=mock_response):
            response = client.post("http://example.com/api", json={"key": "val"})
        assert response.status_code == 200

    def test_post_timeout_raises_client_error(self, client):
        with patch.object(client.session, "request", side_effect=ReadTimeout()):
            with pytest.raises(HTTPClientError):
                client.post("http://example.com/login", data={})


class TestHTTPClientHead:
    def test_head_success(self, client, mock_response):
        with patch.object(client.session, "request", return_value=mock_response):
            response = client.head("http://example.com")
        assert response.status_code == 200

    def test_head_timeout_raises_client_error(self, client):
        with patch.object(client.session, "request", side_effect=ReadTimeout()):
            with pytest.raises(HTTPClientError):
                client.head("http://example.com")


class TestCookieManagement:
    def test_set_cookies_updates_session(self, client):
        client.set_cookies({"token": "xyz"})
        assert client.session.cookies.get("token") == "xyz"

    def test_get_cookies_returns_dict(self, client):
        client.set_cookies({"a": "1", "b": "2"})
        cookies = client.get_cookies()
        assert isinstance(cookies, dict)
        assert cookies["a"] == "1"


class TestHeaderManagement:
    def test_set_headers_updates_session(self, client):
        client.set_headers({"Authorization": "Bearer token123"})
        assert client.session.headers["Authorization"] == "Bearer token123"


class TestProxyBuilder:
    def test_http_proxy(self):
        result = HTTPClient._build_proxy_dict("http://proxy.example.com:3128")
        assert result["http"] == "http://proxy.example.com:3128"
        assert result["https"] == "http://proxy.example.com:3128"

    def test_none_proxy_returns_none(self):
        assert HTTPClient._build_proxy_dict(None) is None
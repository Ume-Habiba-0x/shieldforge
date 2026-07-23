"""Tests for the auth scanner module."""

from unittest.mock import MagicMock

from core.context import Config, Context
from core.models import Severity
from modules.auth import AuthScanner

LOGIN_HTML = """
<html><body>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
</body></html>
"""

NO_FORM_HTML = "<html><body><h1>Welcome</h1></body></html>"

POLICY_HTML = """
<html><body>
<p>Password must be at least 8 characters.</p>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
</body></html>
"""


class FakeCookie:
    def __init__(self, name, secure=False, rest=None):
        self.name = name
        self.secure = secure
        self._rest = rest or {}


class FakeResponse:
    def __init__(self, text="", status_code=200, cookies=None):
        self.text = text
        self.status_code = status_code
        self.cookies = cookies or []


def make_context(target="http://example.test/"):
    context = Context(config=Config(target_url=target))
    context.http_client = MagicMock()
    return context


def test_no_login_form_returns_info_finding():
    context = make_context()
    context.http_client.get.return_value = FakeResponse(text=NO_FORM_HTML)

    result = AuthScanner().scan(context)

    assert not result.errors
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "No login form" in result.findings[0].title


def test_missing_cookie_flags_are_flagged():
    context = make_context()
    cookies = [FakeCookie("session", secure=False, rest={})]
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML, cookies=cookies)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials")

    result = AuthScanner().scan(context)

    cookie_findings = [f for f in result.findings if f.category == "session_cookie"]
    assert len(cookie_findings) == 1
    assert set(cookie_findings[0].evidence["missing_flags"]) == {"Secure", "HttpOnly", "SameSite"}


def test_fully_flagged_cookie_is_not_reported():
    context = make_context()
    cookies = [FakeCookie("session", secure=True, rest={"HttpOnly": None, "SameSite": "Strict"})]
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML, cookies=cookies)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials")

    result = AuthScanner().scan(context)

    assert [f for f in result.findings if f.category == "session_cookie"] == []


def test_case_insensitive_cookie_flags_are_recognized():
    context = make_context()
    cookies = [FakeCookie("session", secure=True, rest={"httponly": None, "samesite": "Lax"})]
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML, cookies=cookies)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials")

    result = AuthScanner().scan(context)

    assert [f for f in result.findings if f.category == "session_cookie"] == []


def test_no_password_policy_hint_is_flagged():
    context = make_context()
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials")

    result = AuthScanner().scan(context)

    policy_findings = [f for f in result.findings if f.category == "weak_password_policy"]
    assert len(policy_findings) == 1


def test_password_policy_text_hint_suppresses_finding():
    context = make_context()
    context.http_client.get.return_value = FakeResponse(text=POLICY_HTML)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials")

    result = AuthScanner().scan(context)

    assert [f for f in result.findings if f.category == "weak_password_policy"] == []


def test_username_enumeration_detected_on_length_difference():
    context = make_context()
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML)
    context.http_client.post.side_effect = [
        FakeResponse(text="Invalid password", status_code=200),
        FakeResponse(text="Invalid username or password, this response is padded to differ", status_code=200),
    ]

    result = AuthScanner().scan(context)

    enum_findings = [f for f in result.findings if f.category == "username_enumeration"]
    assert len(enum_findings) == 1
    assert enum_findings[0].severity == Severity.HIGH


def test_no_enumeration_finding_when_responses_are_identical():
    context = make_context()
    context.http_client.get.return_value = FakeResponse(text=LOGIN_HTML)
    context.http_client.post.return_value = FakeResponse(text="Invalid credentials", status_code=200)

    result = AuthScanner().scan(context)

    assert [f for f in result.findings if f.category == "username_enumeration"] == []


def test_fetch_failure_is_recorded_as_error_not_raised():
    context = make_context()
    context.http_client.get.side_effect = ConnectionError("boom")

    result = AuthScanner().scan(context)

    assert result.errors
    assert result.findings == []

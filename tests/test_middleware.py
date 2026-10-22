"""Tests for the middleware pipeline: retry, redirect, proxy rotation."""
import pytest
from horaa_tls.exceptions import TooManyRedirectsError
from horaa_tls.middleware.proxy import ProxyRotatorMiddleware, normalize_proxy_url
from horaa_tls.middleware.redirect import RedirectMiddleware
from horaa_tls.middleware.retry import RetryMiddleware

from .conftest import make_response


class TestNormalizeProxyUrl:
    @pytest.mark.parametrize("raw,expected", [
        ("1.2.3.4:8080", "http://1.2.3.4:8080"),
        ("user:pass@1.2.3.4:8080", "http://user:pass@1.2.3.4:8080"),
        ("http://1.2.3.4:8080", "http://1.2.3.4:8080"),
        ("socks5h://1.2.3.4:1080", "socks5h://1.2.3.4:1080"),
        ("", ""),
    ])
    def test_normalize(self, raw, expected):
        assert normalize_proxy_url(raw) == expected


class TestRetryMiddleware:
    def test_retries_on_server_error(self):
        mw = RetryMiddleware(jitter=False)
        payload = {"x": 1}
        out = mw.after_response(None, payload, make_response(status=503))
        assert out is not None
        assert out["_retry_attempt"] == 1
        assert out["_retry_delay"] == 0.5  # 0.5 * 2^0

    def test_stops_at_max_retries(self):
        mw = RetryMiddleware(max_retries=2, jitter=False)
        payload = {"_retry_attempt": 2}
        assert mw.after_response(None, payload, make_response(status=500)) is None

    def test_no_retry_on_client_error(self):
        mw = RetryMiddleware()
        assert mw.after_response(None, {}, make_response(status=403)) is None

    def test_no_retry_on_too_many_redirects(self):
        mw = RetryMiddleware()
        err = TooManyRedirectsError("Max redirects exceeded")
        assert mw.after_error(None, {}, err) is None

    def test_retries_on_network_error_with_backoff(self):
        mw = RetryMiddleware(max_retries=3, backoff_factor=1.0, jitter=False)
        out = mw.after_error(None, {}, ConnectionError("boom"))
        assert out["_retry_delay"] == 1.0
        out2 = mw.after_error(None, out, ConnectionError("boom"))
        assert out2["_retry_delay"] == 2.0

    def test_jitter_reduces_delay(self):
        mw = RetryMiddleware(max_retries=5, backoff_factor=2.0, jitter=True)
        delays = [mw._compute_delay(2) for _ in range(20)]
        assert all(0.5 * 8 <= d <= 8 for d in delays)
        assert any(d < 8 for d in delays)  # actually randomized


class TestRedirectMiddleware:
    def _run(self, mw, session, payload, response):
        mw.before_request(session, payload)
        return mw.after_response(session, payload, response)

    def test_before_request_disables_go_redirects(self, session):
        mw = RedirectMiddleware()
        payload = {"followRedirects": True}
        mw.before_request(session, payload)
        assert payload["followRedirects"] is False
        assert payload["_original_follow_redirects"] is True

    def test_follows_redirect(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/one", "headers": {}}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://a.com/two"}))
        assert out["requestUrl"] == "https://a.com/two"
        assert out["requestMethod"] == "GET"

    def test_relative_location_resolved(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/one", "headers": {}}
        out = self._run(mw, session, payload, make_response(status=301, headers={"Location": "/two"}))
        assert out["requestUrl"] == "https://a.com/two"

    def test_max_redirects_raises_distinct_error(self, session):
        mw = RedirectMiddleware(max_redirects=2)
        payload = {"requestUrl": "https://a.com/x", "headers": {}, "_redirect_history": [1, 2]}
        with pytest.raises(TooManyRedirectsError):
            self._run(mw, session, payload, make_response(status=302, headers={"Location": "/y"}))

    def test_allow_redirects_false_stops(self, session):
        mw = RedirectMiddleware()
        # followRedirects=False mirrors what _prepare_payload sets for allow_redirects=False
        payload = {"requestUrl": "https://a.com/x", "headers": {}, "followRedirects": False}
        resp = make_response(status=302, headers={"Location": "/y"})
        assert self._run(mw, session, payload, resp) is None
        assert resp.history == []

    def test_cross_host_strips_authorization(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/x", "headers": {"Authorization": "Bearer tok", "Accept": "*/*"}}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://b.com/y"}))
        assert "authorization" not in {k.lower() for k in out["headers"]}
        assert out["headers"]["Accept"] == "*/*"

    def test_cross_host_filters_foreign_cookies(self, session):
        session._cookie_domains["sid"] = "a.com"
        session.cookies["sid"] = "secret"
        mw = RedirectMiddleware()
        cookies = [{"name": "sid", "value": "secret", "domain": "", "path": "/"}]
        payload = {"requestUrl": "https://a.com/x", "headers": {}, "requestCookies": list(cookies)}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://b.com/y"}))
        assert out["requestCookies"] == []
        # ...but same-host redirects keep them
        payload2 = {"requestUrl": "https://a.com/x", "headers": {}, "requestCookies": list(cookies)}
        out2 = self._run(mw, session, payload2, make_response(status=302, headers={"Location": "https://a.com/y"}))
        assert out2["requestCookies"] == cookies

    def test_307_keeps_method_and_body(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/x", "requestMethod": "POST", "requestBody": "abc",
                   "isByteRequest": False, "headers": {"Content-Type": "text/plain"}}
        out = self._run(mw, session, payload, make_response(status=307, headers={"Location": "/y"}))
        assert out["requestMethod"] == "POST"
        assert out["requestBody"] == "abc"

    def test_head_redirect_keeps_head_method(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/x", "requestMethod": "HEAD", "headers": {}}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "/y"}))
        assert out["requestMethod"] == "HEAD"

    def test_cross_host_with_ports_preserves_auth_on_same_host(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com:8443/x", "headers": {"Authorization": "Bearer tok", "Accept": "*/*"}}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://a.com:8443/y"}))
        assert "authorization" in {k.lower() for k in out["headers"]}

    def test_redirect_does_not_mutate_original_payload_headers(self, session):
        mw = RedirectMiddleware()
        orig_headers = {"Authorization": "Bearer tok", "Content-Type": "text/plain"}
        payload = {"requestUrl": "https://a.com/x", "headers": orig_headers}
        self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://b.com/y"}))
        assert "Authorization" in orig_headers
        assert "Content-Type" in orig_headers

    def test_scheme_downgrade_https_to_http_strips_credentials(self, session):
        mw = RedirectMiddleware()
        payload = {
            "requestUrl": "https://example.com/secure",
            "headers": {"Authorization": "Bearer tok", "Cookie": "sid=123", "Accept": "*/*"},
            "requestCookies": [{"name": "sid", "value": "123", "domain": "", "path": "/"}],
        }
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "http://example.com/unencrypted"}))
        headers_lc = {k.lower(): v for k, v in out["headers"].items()}
        assert "authorization" not in headers_lc
        assert "cookie" not in headers_lc
        assert out["requestCookies"] == []
        assert headers_lc["accept"] == "*/*"

    def test_cross_port_redirect_strips_credentials(self, session):
        mw = RedirectMiddleware()
        payload = {
            "requestUrl": "https://a.com:8443/x",
            "headers": {"Authorization": "Bearer tok", "Accept": "*/*"},
        }
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "https://a.com:443/y"}))
        headers_lc = {k.lower(): v for k, v in out["headers"].items()}
        assert "authorization" not in headers_lc

    def test_redirect_carries_url_fragment(self, session):
        mw = RedirectMiddleware()
        payload = {"requestUrl": "https://a.com/x#section1", "headers": {}}
        out = self._run(mw, session, payload, make_response(status=302, headers={"Location": "/y"}))
        assert out["requestUrl"] == "https://a.com/y#section1"

    def test_redirect_strips_transfer_encoding_on_method_change(self, session):
        mw = RedirectMiddleware()
        payload = {
            "requestUrl": "https://a.com/x",
            "requestMethod": "POST",
            "headers": {"Transfer-Encoding": "chunked", "Content-Type": "text/plain"},
        }
        out = self._run(mw, session, payload, make_response(status=303, headers={"Location": "/y"}))
        assert out["requestMethod"] == "GET"
        headers_lc = {k.lower(): v for k, v in out["headers"].items()}
        assert "transfer-encoding" not in headers_lc
        assert "content-type" not in headers_lc

    @pytest.mark.parametrize("status,method,expected_method,expect_body_cleared", [
        # 303 See Other: turns any method except HEAD into GET
        (303, "GET", "GET", False),
        (303, "HEAD", "HEAD", False),
        (303, "POST", "GET", True),
        (303, "PUT", "GET", True),
        (303, "PATCH", "GET", True),
        (303, "DELETE", "GET", True),
        (303, "OPTIONS", "GET", True),
        # 301 Moved Permanently: turns POST into GET; preserves others
        (301, "GET", "GET", False),
        (301, "HEAD", "HEAD", False),
        (301, "POST", "GET", True),
        (301, "PUT", "PUT", False),
        (301, "PATCH", "PATCH", False),
        (301, "DELETE", "DELETE", False),
        (301, "OPTIONS", "OPTIONS", False),
        # 302 Found: turns POST into GET; preserves others
        (302, "GET", "GET", False),
        (302, "HEAD", "HEAD", False),
        (302, "POST", "GET", True),
        (302, "PUT", "PUT", False),
        (302, "PATCH", "PATCH", False),
        (302, "DELETE", "DELETE", False),
        (302, "OPTIONS", "OPTIONS", False),
        # 307 Temporary Redirect: preserves all methods and bodies
        (307, "GET", "GET", False),
        (307, "HEAD", "HEAD", False),
        (307, "POST", "POST", False),
        (307, "PUT", "PUT", False),
        (307, "PATCH", "PATCH", False),
        (307, "DELETE", "DELETE", False),
        (307, "OPTIONS", "OPTIONS", False),
        # 308 Permanent Redirect: preserves all methods and bodies
        (308, "GET", "GET", False),
        (308, "HEAD", "HEAD", False),
        (308, "POST", "POST", False),
        (308, "PUT", "PUT", False),
        (308, "PATCH", "PATCH", False),
        (308, "DELETE", "DELETE", False),
        (308, "OPTIONS", "OPTIONS", False),
    ])
    def test_redirect_method_matrix(self, session, status, method, expected_method, expect_body_cleared):
        mw = RedirectMiddleware()
        payload = {
            "requestUrl": "https://a.com/resource",
            "requestMethod": method,
            "requestBody": "initial body",
            "isByteRequest": False,
            "headers": {"Content-Type": "text/plain", "Transfer-Encoding": "chunked"},
        }
        out = self._run(mw, session, payload, make_response(status=status, headers={"Location": "/target"}))
        assert out["requestMethod"] == expected_method
        if expect_body_cleared:
            assert out["requestBody"] == ""
            assert out["isByteRequest"] is False
            headers_lc = {k.lower(): v for k, v in out["headers"].items()}
            assert "content-type" not in headers_lc
            assert "transfer-encoding" not in headers_lc
        else:
            if method not in ("GET", "HEAD"):
                assert out["requestBody"] == "initial body"

    def test_multi_hop_credential_isolation(self, session):
        """Verifies that credentials stripped on hop 1 are never reintroduced on subsequent hops."""
        mw = RedirectMiddleware()
        p0 = {
            "requestUrl": "https://source.com/hop1",
            "requestMethod": "GET",
            "headers": {"Authorization": "SecretToken", "Cookie": "sid=1"},
            "requestCookies": [{"name": "sid", "value": "1", "domain": "", "path": "/"}],
        }
        # Hop 1 -> external.com (cross-host)
        p1 = self._run(mw, session, p0, make_response(status=302, headers={"Location": "https://external.com/hop2"}))
        assert "authorization" not in {k.lower() for k in p1["headers"]}
        assert "cookie" not in {k.lower() for k in p1["headers"]}

        # Hop 2 -> external.com/hop3 (same-host on external.com)
        p2 = self._run(mw, session, p1, make_response(status=302, headers={"Location": "https://external.com/hop3"}))
        # Ensure credentials from source.com did not magically reappear
        assert "authorization" not in {k.lower() for k in p2["headers"]}
        assert "cookie" not in {k.lower() for k in p2["headers"]}
        assert len(p2["_redirect_history"]) == 2


class TestProxyRotatorMiddleware:
    def test_request_mode_rotates_every_request(self):
        mw = ProxyRotatorMiddleware(proxies=["p1:1", "p2:1"], mode="request")
        p1, p2, p3 = {}, {}, {}
        mw.before_request(None, p1)
        mw.before_request(None, p2)
        mw.before_request(None, p3)
        assert p1["proxyUrl"] == "http://p1:1"
        assert p2["proxyUrl"] == "http://p2:1"
        assert p3["proxyUrl"] == "http://p1:1"

    def test_failover_on_403(self):
        mw = ProxyRotatorMiddleware(proxies=["http://p1:1", "http://p2:1"], mode="failover")
        payload = {"proxyUrl": "http://p1:1"}
        out = mw.after_response(None, payload, make_response(status=403))
        assert out is not None
        assert out["proxyUrl"] == "http://p2:1"
        assert out["_proxy_failover_count"] == 1

    def test_failover_respects_max_failovers(self):
        mw = ProxyRotatorMiddleware(proxies=["http://p1:1", "http://p2:1"], mode="failover", max_failovers=1)
        payload = {"proxyUrl": "http://p1:1", "_proxy_failover_count": 1}
        assert mw.after_response(None, payload, make_response(status=403)) is None

    def test_no_failover_on_success(self):
        mw = ProxyRotatorMiddleware(proxies=["http://p1:1"], mode="failover")
        assert mw.after_response(None, {"proxyUrl": "http://p1:1"}, make_response(status=200)) is None

    def test_failover_on_network_error(self):
        mw = ProxyRotatorMiddleware(proxies=["http://p1:1", "http://p2:1"], mode="failover")
        out = mw.after_error(None, {"proxyUrl": "http://p1:1"}, ConnectionError("refused"))
        assert out["proxyUrl"] == "http://p2:1"

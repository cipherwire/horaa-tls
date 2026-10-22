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


class TestProxyRotatorMiddleware:
    def test_request_mode_rotates_every_request(self):
        mw = ProxyRotatorMiddleware(proxies=["p1:1", "p2:1"], mode="request")
        p1, p2 = {}, {}
        mw.before_request(None, p1)
        mw.before_request(None, p2)
        assert p1["proxyUrl"] != p2["proxyUrl"]

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

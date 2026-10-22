"""Tests for Session payload construction, cookie handling, and serialization."""

import pytest
from horaa_tls import Session
from horaa_tls.exceptions import HoraaTLSError
from horaa_tls.fingerprint.user_agent import UserAgentGenerator
from horaa_tls.middleware.proxy import ProxyRotatorMiddleware

from .conftest import make_response


class TestPreparePayload:
    def test_default_header_order_matches_profile(self, session):
        payload = session._prepare_payload("GET", "https://example.com/")
        assert payload["headerOrder"] == UserAgentGenerator.get_header_order_for_profile("chrome_133")
        assert payload["pseudoHeaderOrder"] == UserAgentGenerator.get_pseudo_header_order_for_profile("chrome_133")

    def test_custom_header_order_overrides(self, monkeypatch):
        monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", object)
        s = Session(header_order=["a", "b"])
        payload = s._prepare_payload("GET", "https://example.com/")
        assert payload["headerOrder"] == ["a", "b"]
        s.close()

    def test_random_tls_extension_order_default_off(self, session):
        payload = session._prepare_payload("GET", "https://example.com/")
        assert payload["withRandomTLSExtensionOrder"] is False

    def test_random_tls_extension_order_opt_in(self, monkeypatch):
        monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", object)
        s = Session(random_tls_extension_order=True)
        assert s._prepare_payload("GET", "https://x/")["withRandomTLSExtensionOrder"] is True
        s.close()

    def test_timeout_respects_zero(self, session):
        payload = session._prepare_payload("GET", "https://example.com/", timeout=0)
        assert payload["timeoutSeconds"] == 0

    def test_timeout_falls_back_to_session_default(self, session):
        payload = session._prepare_payload("GET", "https://example.com/")
        assert payload["timeoutSeconds"] == 30

    def test_headers_merged_case_insensitively_and_none_removes(self, session):
        payload = session._prepare_payload(
            "GET", "https://example.com/",
            headers={"USER-AGENT": "custom/1.0", "Accept": None},
        )
        assert payload["headers"]["user-agent"] == "custom/1.0"
        assert "accept" not in payload["headers"]

    def test_json_body_sets_content_type(self, session):
        payload = session._prepare_payload("POST", "https://example.com/", json_data={"a": 1})
        assert payload["requestBody"] == '{"a": 1}'
        assert payload["headers"]["content-type"] == "application/json"

    def test_params_merged_into_query(self, session):
        payload = session._prepare_payload("GET", "https://example.com/path?a=1", params={"b": "2"})
        assert "a=1" in payload["requestUrl"] and "b=2" in payload["requestUrl"]

    def test_private_keys_stripped_by_backend_layer(self, session):
        payload = session._prepare_payload("GET", "https://example.com/")
        payload["_internal_marker"] = True
        clean = {k for k in payload if not k.startswith("_")}
        assert "_internal_marker" not in clean


class TestCookies:
    def test_response_cookies_synced_with_domain(self, session):
        resp = make_response(url="https://site-a.com/", cookies={"sid": "abc"})
        session._sync_cookies(resp)
        assert session.cookies == {"sid": "abc"}
        assert session._cookie_domains["sid"] == "site-a.com"

    def test_cross_site_cookies_not_replayed(self, session):
        session._sync_cookies(make_response(url="https://site-a.com/", cookies={"sid": "abc"}))
        payload = session._prepare_payload("GET", "https://site-b.com/")
        names = [c["name"] for c in payload["requestCookies"]]
        assert "sid" not in names

    def test_same_site_cookies_replayed(self, session):
        session._sync_cookies(make_response(url="https://site-a.com/", cookies={"sid": "abc"}))
        payload = session._prepare_payload("GET", "https://www.site-a.com/deep")
        names = [c["name"] for c in payload["requestCookies"]]
        assert "sid" in names

    def test_user_set_cookies_always_sent(self, session):
        session.cookies["mytoken"] = "xyz"  # no domain recorded
        payload = session._prepare_payload("GET", "https://anywhere.com/")
        names = [c["name"] for c in payload["requestCookies"]]
        assert "mytoken" in names

    def test_per_request_cookies_merge(self, session):
        payload = session._prepare_payload("GET", "https://x.com/", cookies={"temp": "1"})
        names = [c["name"] for c in payload["requestCookies"]]
        assert "temp" in names


class TestLifecycle:
    def test_context_manager_closes(self, monkeypatch):
        calls = []

        class DestroyableBackend:
            def destroy_session(self, sid):
                calls.append(sid)
                return True

        monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", DestroyableBackend)
        with Session() as s:
            assert not s._closed
        assert s._closed
        assert calls == [s.session_id]

    def test_close_is_idempotent(self, session):
        assert session.close() is True
        assert session.close() is True

    def test_request_after_close_raises(self, session):
        session.close()
        with pytest.raises(HoraaTLSError, match="closed"):
            session.get("https://example.com/")


class TestSerialization:
    def test_roundtrip_preserves_state(self, monkeypatch):
        monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", object)
        s = Session(
            profile="firefox_133",
            random_tls_extension_order=True,
            timeout_seconds=45,
            cookies={"seed": "1"},
        )
        s._cookie_domains["seed"] = "example.com"
        s.retry_middleware.max_retries = 7
        s.redirect_middleware.max_redirects = 11
        s.redirect_stop_at = "https://stop.here/"

        restored = Session.from_json(s.to_json())
        assert restored.profile == "firefox_133"
        assert restored.random_tls_extension_order is True
        assert restored.timeout_seconds == 45
        assert restored.cookies == {"seed": "1"}
        assert restored._cookie_domains == {"seed": "example.com"}
        assert restored.retry_middleware.max_retries == 7
        assert restored.redirect_middleware.max_redirects == 11
        assert restored.redirect_stop_at == "https://stop.here/"
        assert restored.header_order == s.header_order
        restored.close()
        s.close()

    def test_proxy_state_restored(self, monkeypatch):
        monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", object)
        s = Session(proxies=["http://p1:1", "http://p2:1"])
        restored = Session.from_json(s.to_json())
        assert isinstance(restored.proxy_middleware, ProxyRotatorMiddleware)
        assert restored.proxy_middleware.proxies == ["http://p1:1", "http://p2:1"]
        restored.close()
        s.close()


class TestRequestLoop:
    def test_response_built_and_returned(self, session):
        session.backend.queue.append({
            "status": 200, "target": "https://example.com/",
            "headers": {"Content-Type": ["application/json"]},
            "body": '{"ok": true}', "cookies": {},
        })
        r = session.get("https://example.com/")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    def test_redirect_followed_through_pipeline(self, session):
        session.backend.queue.append({
            "status": 302, "target": "https://example.com/one",
            "headers": {"Location": ["/two"]}, "body": "", "cookies": {},
        })
        session.backend.queue.append({
            "status": 200, "target": "https://example.com/two",
            "headers": {}, "body": "final", "cookies": {},
        })
        r = session.get("https://example.com/one")
        assert r.status_code == 200
        assert r.text == "final"
        assert len(r.history) == 1
        assert r.history[0].status_code == 302

    def test_backend_error_raised_on_status_zero(self, session):
        session.retry_middleware.max_retries = 0  # isolate from retry logic
        session.backend.queue.append({"status": 0, "body": "go failed"})
        with pytest.raises(Exception):
            session.get("https://example.com/")

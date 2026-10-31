"""Regression test suite for verified bugs and edge cases."""

import gc
from unittest.mock import MagicMock

from horaa_tls import Session
from horaa_tls.response import Response, build_response


def test_cookie_expiration_and_deletion_sync():
    """Verify that Set-Cookie headers with Max-Age=0 or expired dates purge cookies from Session."""
    session = Session(cookies={"session_token": "active_val", "auth_token": "login_val", "persistent": "keep_val"})
    response = Response()
    response.url = "https://example.com/logout"
    # Simulated Set-Cookie headers indicating deletion
    response.headers["Set-Cookie"] = "session_token=; Max-Age=0; Path=/"
    response.headers._list_store["set-cookie"] = [
        "session_token=; Max-Age=0; Path=/",
        "auth_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
    ]
    # Go engine cookie jar returns only non-expired cookies
    response.cookies = {"persistent": "keep_val"}

    session._sync_cookies(response)

    assert "session_token" not in session.cookies
    assert "auth_token" not in session.cookies
    assert session.cookies.get("persistent") == "keep_val"
    session.close()


def test_subsecond_timeout_resolution():
    """Verify subsecond and fractional timeouts are mapped to timeoutMilliseconds in Go FFI."""
    session = Session()

    # Sub-second duration
    res_sub = session._resolve_timeout_payload(0.5)
    assert res_sub == {"timeoutMilliseconds": 500}

    # Fractional duration
    res_frac = session._resolve_timeout_payload(2.25)
    assert res_frac == {"timeoutMilliseconds": 2250}

    # Whole second duration
    res_whole = session._resolve_timeout_payload(10)
    assert res_whole == {"timeoutSeconds": 10}

    # Zero timeout (disabled)
    res_zero = session._resolve_timeout_payload(0)
    assert res_zero == {"timeoutSeconds": 0}

    session.close()


def test_session_finalizer_garbage_collection():
    """Verify Session.__del__ triggers close() and cleans up the Go backend session.

    A session that never issued a request has no Go-side client: the finalizer must
    skip the destroy FFI call (which would otherwise load the native library just to
    free nothing). A session that issued a request must be destroyed exactly once.
    """
    # 1. Never-used session: finalizer must not call destroy.
    session = Session()
    mock_destroy = MagicMock(return_value=True)
    session.backend.destroy_session = mock_destroy
    del session
    gc.collect()
    mock_destroy.assert_not_called()

    # 2. Used session: finalizer must destroy the Go-side client exactly once.
    session = Session()
    mock_destroy = MagicMock(return_value=True)
    session.backend.destroy_session = mock_destroy
    session.backend.execute = lambda payload: {
        "status": 200, "target": payload.get("requestUrl", ""),
        "headers": {}, "body": "", "cookies": {},
    }
    session.get("https://example.com/")
    session_id = session.session_id
    del session
    gc.collect()
    mock_destroy.assert_called_once_with(session_id)


def test_user_agent_none_suppresses_go_signature():
    """Verify headers={'User-Agent': None} sets empty string to suppress Go-http-client fallback."""
    session = Session()
    payload = session._prepare_payload("GET", "https://example.com/", headers={"User-Agent": None})
    assert payload["headers"].get("user-agent") == ""
    session.close()


def test_ip_host_set_cookie_preserved_in_response():
    """Verify cookies with IP address domains are retained in Response.cookies."""
    raw_resp = {
        "status": 200,
        "target": "http://127.0.0.1:8080/",
        "headers": {
            "Set-Cookie": ["session_id=12345; Path=/", "tracker=trk_99; Domain=127.0.0.1; Path=/"]
        },
        "cookies": {
            "session_id": "12345"
            # Go jar dropped tracker due to Domain=127.0.0.1 RFC 6265 strictness
        },
        "body": "ok",
    }
    response = build_response(raw_resp)
    assert response.cookies.get("session_id") == "12345"
    assert response.cookies.get("tracker") == "trk_99"

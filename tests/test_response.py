"""Tests for CaseInsensitiveDict, Protocol and Response building."""
import json

import pytest
from horaa_tls.response import CaseInsensitiveDict, Protocol, build_response


class TestCaseInsensitiveDict:
    def test_case_insensitive_access(self):
        h = CaseInsensitiveDict({"Content-Type": "application/json"})
        assert h["content-type"] == "application/json"
        assert h["CONTENT-TYPE"] == "application/json"
        assert h.get("CoNtEnT-tYpE") == "application/json"
        assert "content-type" in h

    def test_json_serialization_preserves_keys(self):
        h = CaseInsensitiveDict({"Content-Type": "application/json", "X-Test": "1"})
        assert json.loads(json.dumps(h)) == {"Content-Type": "application/json", "X-Test": "1"}

    def test_equality_with_plain_dict(self):
        h = CaseInsensitiveDict({"Content-Type": "application/json"})
        assert h == {"Content-Type": "application/json"}
        assert h != {"Content-Type": "text/html"}

    def test_pop_works(self):
        h = CaseInsensitiveDict({"Content-Type": "application/json"})
        assert h.pop("CONTENT-TYPE") == "application/json"
        assert "content-type" not in h
        assert len(h) == 0
        with pytest.raises(KeyError):
            h.pop("missing")
        assert h.pop("missing", "default") == "default"

    def test_setdefault(self):
        h = CaseInsensitiveDict({"A": "1"})
        assert h.setdefault("a", "2") == "1"
        assert h.setdefault("B", "3") == "3"

    def test_delitem(self):
        h = CaseInsensitiveDict({"X-Test": "1"})
        del h["x-test"]
        assert dict(h) == {}

    def test_setitem_keeps_first_casing(self):
        h = CaseInsensitiveDict()
        h["Content-Type"] = "a"
        h["CONTENT-TYPE"] = "b"
        assert list(h.keys()) == ["Content-Type"]
        assert h["content-type"] == "b"

    def test_copy_is_independent(self):
        h = CaseInsensitiveDict({"A": "1"})
        h2 = h.copy()
        h2["a"] = "2"
        assert h["A"] == "1"

    def test_iteration_and_len(self):
        h = CaseInsensitiveDict({"A": "1", "B": "2"})
        assert len(h) == 2
        assert sorted(h.keys()) == ["A", "B"]
        assert sorted(h.values()) == ["1", "2"]
        assert sorted(h.items()) == [("A", "1"), ("B", "2")]


class TestProtocol:
    @pytest.mark.parametrize("value,expected", [
        ("HTTP/2.0", Protocol.HTTP_2),
        ("h2", Protocol.HTTP_2),
        ("HTTP/1.1", Protocol.HTTP_1_1),
        ("QUIC", Protocol.HTTP_3),
        ("", None),
        (None, None),
        ("nonsense", None),
    ])
    def test_from_string(self, value, expected):
        assert Protocol.from_string(value) is expected


class TestBuildResponse:
    def test_headers_list_joining(self):
        r = build_response({"status": 200, "target": "http://x", "headers": {"Set-Cookie": ["a=1", "b=2"]}})
        assert r.headers["set-cookie"] == "a=1, b=2"

    def test_cookies_dict_form(self):
        r = build_response({"status": 200, "headers": {}, "cookies": {"sid": "abc"}})
        assert r.cookies == {"sid": "abc"}

    def test_cookies_list_form(self):
        r = build_response({"status": 200, "headers": {}, "cookies": [{"name": "sid", "value": "abc"}]})
        assert r.cookies == {"sid": "abc"}

    def test_data_uri_body_decoded(self):
        r = build_response({"status": 200, "headers": {}, "body": "data:application/octet-stream;base64,SGVsbG8="}, is_byte_response=True)
        assert r.content == b"Hello"

    def test_plain_base64_body_decoded(self):
        r = build_response({"status": 200, "headers": {}, "body": "SGVsbG8="}, is_byte_response=True)
        assert r.content == b"Hello"

    def test_invalid_base64_falls_back_to_utf8(self):
        # Not valid base64 (spaces/punctuation) -> must fall back to raw text, not crash.
        r = build_response({"status": 200, "headers": {}, "body": "hello world!!!"}, is_byte_response=True)
        assert r.content == b"hello world!!!"

    def test_non_byte_response_stays_text(self):
        r = build_response({"status": 200, "headers": {}, "body": "plain"}, is_byte_response=False)
        assert r.content == b"plain"

    def test_ok_and_is_redirect(self):
        assert build_response({"status": 200, "headers": {}}).ok is True
        assert build_response({"status": 404, "headers": {}}).ok is False
        redir = build_response({"status": 302, "headers": {"Location": "/next"}})
        assert redir.is_redirect is True
        assert build_response({"status": 302, "headers": {}}).is_redirect is False

    def test_text_charset(self):
        import base64
        # latin-1 bytes delivered via the byte-response (base64) contract
        raw = "caf\xe9".encode("iso-8859-1")
        r = build_response(
            {"status": 200,
             "headers": {"Content-Type": "text/html; charset=ISO-8859-1"},
             "body": base64.b64encode(raw).decode()},
            is_byte_response=True,
        )
        assert r.content == raw
        assert r.text == "café"

    def test_json_bom_tolerated(self):
        r = build_response({"status": 200, "headers": {}, "body": "\ufeff{\"a\": 1}"})
        assert r.json() == {"a": 1}

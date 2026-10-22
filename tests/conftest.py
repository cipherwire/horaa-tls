"""Shared fixtures: a fake backend so no test touches the network or the Go library."""
import pytest
from horaa_tls.client import Session
from horaa_tls.response import build_response


class FakeBackend:
    """Records payloads and replays canned raw responses queued by the test."""

    def __init__(self):
        self.payloads = []
        self.queue = []

    def execute(self, payload):
        self.payloads.append(payload)
        raw = self.queue.pop(0) if self.queue else {
            "status": 200, "target": payload.get("requestUrl", ""),
            "headers": {}, "body": "", "cookies": {},
        }
        return raw

    async def execute_async(self, payload):
        return self.execute(payload)

    def get_cookies(self, session_id, url):
        return []

    def add_cookies(self, session_id, url, cookies):
        return []

    def destroy_session(self, session_id):
        return True


@pytest.fixture
def session(monkeypatch):
    """A Session with the real FFI backend swapped for FakeBackend."""
    monkeypatch.setattr("horaa_tls.client.CtypesGoBackend", FakeBackend)
    s = Session(profile="chrome_133")
    yield s
    s.close()


def make_response(status=200, url="https://example.com/", headers=None, body="", cookies=None):
    return build_response(
        {
            "status": status,
            "target": url,
            "headers": headers or {},
            "body": body,
            "cookies": cookies or {},
        },
        is_byte_response=False,
    )

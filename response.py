import base64
import json
from collections.abc import Mapping
from enum import Enum
from typing import Any, Optional

from horaa_tls.exceptions import NetworkError


class CaseInsensitiveDict(dict):
    """
    A case-insensitive dictionary for HTTP headers.

    Data is stored *both* in the underlying dict (with the last-set casing, so
    ``json.dumps`` / ``==`` / iteration behave like a normal dict) and in a
    lowercase lookup map, giving true case-insensitive access::

        h = CaseInsensitiveDict({"Content-Type": "application/json"})
        h["content-type"]          # -> "application/json"
        json.dumps(h)              # -> '{"Content-Type": "application/json"}'
        h == {"content-type": "application/json"}   # -> True
        h.pop("CONTENT-TYPE")      # -> "application/json"
    """

    def __init__(self, data=None, **kwargs):
        super().__init__()
        self._store: dict[str, tuple] = {}
        self._list_store: dict[str, list[Any]] = {}
        if data:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _lower(key: Any) -> Any:
        return key.lower() if isinstance(key, str) else key

    def _remember(self, key: str, value: Any):
        lc = self._lower(key)
        existing = self._store.get(lc)
        cased_key = existing[0] if existing else key
        # Keep the first-seen casing in the visible dict for stable output.
        if existing:
            super().__setitem__(cased_key, value)
        else:
            super().__setitem__(key, value)
        self._store[lc] = (cased_key, value)
        if isinstance(value, list):
            self._list_store[lc] = list(value)
        else:
            self._list_store[lc] = [value]

    def _forget(self, key: str):
        lc = self._lower(key)
        self._list_store.pop(lc, None)
        entry = self._store.pop(lc, None)
        if entry:
            super().__delitem__(entry[0])

    # -- case-insensitive access --------------------------------------------

    def __setitem__(self, key: str, value: Any):
        self._remember(key, value)

    def __getitem__(self, key: str) -> Any:
        return self._store[self._lower(key)][1]

    def __delitem__(self, key: str):
        lc = self._lower(key)
        if lc not in self._store:
            raise KeyError(key)
        self._forget(key)

    def __contains__(self, key) -> bool:
        return self._lower(key) in self._store

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key in self:
            return self[key]
        self[key] = default
        return default

    def popitem(self) -> tuple[str, Any]:
        cased_key, value = super().popitem()
        self._store.pop(self._lower(cased_key), None)
        return cased_key, value

    def pop(self, key: str, *default):
        try:
            value = self[key]
        except KeyError:
            if default:
                return default[0]
            raise
        self._forget(key)
        return value

    # -- dict-compatible bulk operations -------------------------------------

    def update(self, other=None, **kwargs):
        if other:
            if hasattr(other, "keys"):
                for k in other.keys():
                    self[k] = other[k]
            else:
                for k, v in other:
                    self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def clear(self):
        super().clear()
        self._store.clear()

    def copy(self):
        return CaseInsensitiveDict(dict(super().items()))

    def getlist(self, key: str, default: Any = None) -> list[Any]:
        """
        Returns all values for the header key as a list.
        Standard for multi-valued headers such as Set-Cookie.
        """
        lc = self._lower(key)
        if lc in self._list_store:
            return list(self._list_store[lc])
        return default if default is not None else []

    get_all = getlist

    # -- equality -------------------------------------------------------------

    def __eq__(self, other) -> bool:
        if isinstance(other, CaseInsensitiveDict):
            return {k: v[1] for k, v in self._store.items()} == {k: v[1] for k, v in other._store.items()}
        if isinstance(other, (dict, Mapping)):
            return {k: v[1] for k, v in self._store.items()} == {k: v[1] for k, v in CaseInsensitiveDict(other)._store.items()}
        return NotImplemented

    def __ne__(self, other) -> bool:
        result = self.__eq__(other)
        return NotImplemented if result is NotImplemented else not result

    # Mappings are unhashable; keep that behavior explicit.
    __hash__ = None

    def __repr__(self) -> str:
        return f"CaseInsensitiveDict({dict(super().items())})"


class Protocol(Enum):
    HTTP_1_1 = "HTTP/1.1"
    HTTP_2 = "HTTP/2.0"
    HTTP_3 = "HTTP/3.0"

    @classmethod
    def from_string(cls, value: str) -> Optional['Protocol']:
        if not value:
            return None
        val = value.upper().strip()
        if val in ("H2", "HTTP/2", "HTTP/2.0"):
            return cls.HTTP_2
        if val in ("H1", "HTTP/1", "HTTP/1.1"):
            return cls.HTTP_1_1
        if val in ("HTTP/3", "HTTP/3.0", "QUIC"):
            return cls.HTTP_3

        for member in cls:
            if member.value.upper() == val:
                return member
        return None


class Response:
    """
    Unified Response object mimicking requests/httpx API.
    """
    def __init__(self):
        self.url: str = ""
        self.status_code: int = 0
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.cookies: dict[str, str] = {}
        self.history: list[Response] = []
        self.used_protocol: Protocol | None = None

        self._content: bytes = b""
        self._text: str | None = None

    @property
    def content(self) -> bytes:
        """Raw response body as bytes."""
        return self._content

    def _infer_charset(self) -> str | None:
        """Best-effort charset extraction from the Content-Type header."""
        content_type = self.headers.get("Content-Type", "")
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip().strip('"').strip("'")
            if charset:
                try:
                    "x".encode(charset)
                    return charset
                except (LookupError, TypeError):
                    return None
        return None

    @property
    def text(self) -> str:
        """Response body as string, honoring the declared charset (UTF-8 fallback)."""
        if self._text is None:
            charset = self._infer_charset() or "utf-8"
            try:
                self._text = self._content.decode(charset, errors="replace")
            except (LookupError, TypeError):
                self._text = self._content.decode("utf-8", errors="replace")
            except Exception:
                self._text = ""
        return self._text

    def json(self, **kwargs) -> Any:
        """Parses the response body as JSON (tolerates a leading BOM)."""
        text = self.text
        if text.startswith("\ufeff"):
            text = text.lstrip("\ufeff")
        return json.loads(text, **kwargs)

    def raise_for_status(self):
        """Raises a NetworkError if HTTP status code represents a client or server error."""
        if 400 <= self.status_code < 600:
            raise NetworkError(f"HTTP Error {self.status_code} for url: {self.url}")

    @property
    def ok(self) -> bool:
        """True when the status code is below 400."""
        return self.status_code < 400

    @property
    def is_redirect(self) -> bool:
        """True when the response is a 3xx carrying a Location header."""
        return self.status_code in (301, 302, 303, 307, 308) and "location" in self.headers

    @property
    def protocol(self) -> Protocol | None:
        """Returns the negotiated HTTP protocol enum (HTTP_1_1, HTTP_2, HTTP_3)."""
        return self.used_protocol

    def iter_content(self, chunk_size: int = 128, decode_unicode: bool = False):
        """
        Iterates over the response body in chunks.
        """
        if chunk_size is not None and chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer or None")

        data = self.text if decode_unicode else self.content
        if not data:
            return

        if chunk_size is None:
            yield data
            return

        length = len(data)
        for i in range(0, length, chunk_size):
            yield data[i:i + chunk_size]

    def iter_lines(self, chunk_size: int = 512, decode_unicode: bool | None = None, delimiter: str | bytes | None = None):
        """
        Iterates over the response body, one line at a time.
        When decode_unicode is True (or default), yields strings; otherwise bytes.
        """
        if decode_unicode is None:
            decode_unicode = True

        pending = "" if decode_unicode else b""
        delims = [delimiter] if delimiter else (["\r\n", "\n", "\r"] if decode_unicode else [b"\r\n", b"\n", b"\r"])

        for chunk in self.iter_content(chunk_size=chunk_size, decode_unicode=decode_unicode):
            pending += chunk
            while True:
                earliest_idx = -1
                matched_delim = None
                for d in delims:
                    idx = pending.find(d)
                    if idx != -1 and (earliest_idx == -1 or idx < earliest_idx):
                        earliest_idx = idx
                        matched_delim = d

                if earliest_idx != -1 and matched_delim is not None:
                    line = pending[:earliest_idx]
                    pending = pending[earliest_idx + len(matched_delim):]
                    yield line
                else:
                    break
        if pending:
            yield pending

    def close(self) -> None:
        """Releases response resources (idempotent, conforms to requests/httpx API)."""
        pass

    def __enter__(self) -> 'Response':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"


def build_response(raw_resp: dict[str, Any], is_byte_response: bool = False) -> Response:
    """
    Factory function to build a Response object from the backend raw response dictionary.

    Body contract: when ``isByteResponse`` is enabled the Go library always
    returns the body as standard base64 (optionally as a ``data:...`` URI).
    Anything that fails strict base64 decoding falls back to raw UTF-8 bytes so
    plain-text error bodies are never silently mangled.
    """
    response = Response()
    response.url = raw_resp.get("target", "")
    response.status_code = raw_resp.get("status", 0)
    response.used_protocol = Protocol.from_string(raw_resp.get("usedProtocol"))

    # Map headers to CaseInsensitiveDict
    headers_dict = CaseInsensitiveDict()
    raw_headers = raw_resp.get("headers", {})
    for key, values in raw_headers.items():
        # Go tls-client headers return values as a list.
        if isinstance(values, list):
            headers_dict[key] = values[0] if len(values) == 1 else ", ".join(values)
            headers_dict._list_store[key.lower()] = list(values)
        else:
            headers_dict[key] = str(values)
            headers_dict._list_store[key.lower()] = [str(values)]
    response.headers = headers_dict

    # Map body content
    raw_body = raw_resp.get("body", "")
    if is_byte_response and isinstance(raw_body, str):
        if raw_body.startswith("data:") and "," in raw_body:
            base64_str = raw_body.split(",", 1)[1]
            try:
                response._content = base64.b64decode(base64_str, validate=True)
            except Exception:
                response._content = raw_body.encode("utf-8")
        else:
            try:
                response._content = base64.b64decode(raw_body, validate=True)
            except Exception:
                response._content = raw_body.encode("utf-8")
    else:
        response._content = raw_body.encode("utf-8") if isinstance(raw_body, str) else b""

    # The Go tls-client returns cookies as a map ({name: value}); handle list form too.
    raw_cookies = raw_resp.get("cookies", {})
    if isinstance(raw_cookies, dict):
        response.cookies.update(raw_cookies)
    elif isinstance(raw_cookies, list):
        for cookie in raw_cookies:
            if isinstance(cookie, dict) and "name" in cookie and "value" in cookie:
                response.cookies[cookie["name"]] = cookie["value"]

    return response

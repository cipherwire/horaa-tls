import urllib.parse
from typing import Any

from horaa_tls.exceptions import TooManyRedirectsError
from horaa_tls.log import logger
from horaa_tls.middleware.base import BaseMiddleware
from horaa_tls.response import Response

# Headers that must not leak to a different host on redirect.
_CREDENTIAL_HEADERS = ("authorization", "proxy-authorization", "cookie")


class RedirectMiddleware(BaseMiddleware):
    """
    Middleware that intercept 3xx response status codes and manually
    resolves redirects, preventing irregular client redirection behaviors.
    """

    def __init__(self, max_redirects: int = 20):
        self.max_redirects = max_redirects

    def before_request(self, session, payload: dict[str, Any]) -> None:
        # Save user's original followRedirects preference if not already recorded
        if "_original_follow_redirects" not in payload:
            payload["_original_follow_redirects"] = payload.get("followRedirects", True)
        # Disable Go's automatic redirection handling so Python can resolve them manually
        payload["followRedirects"] = False

    def after_response(
        self, session, payload: dict[str, Any], response: Response
    ) -> dict[str, Any] | None:
        # If user explicitly set allow_redirects=False, do not follow redirects
        if not payload.get("_original_follow_redirects", True):
            response.history = payload.get("_redirect_history", [])
            return None

        # If the status code is not in the redirect range, assign history and terminate
        if not (300 <= response.status_code < 400):
            response.history = payload.get("_redirect_history", [])
            return None

        # Check for Location header
        location = response.headers.get("Location")
        if not location:
            response.history = payload.get("_redirect_history", [])
            return None

        # Standard-compliant URL joining (fixes relative and absolute url parsing bugs)
        request_url = payload["requestUrl"]
        new_url = urllib.parse.urljoin(request_url, location)
        old_frag = urllib.parse.urlsplit(request_url).fragment
        if old_frag and not urllib.parse.urlsplit(new_url).fragment:
            new_url = f"{new_url}#{old_frag}"

        # Retrieve/initialize history in active payload
        history: list[Response] = payload.setdefault("_redirect_history", [])

        # Check stop conditions if specified on the session. These run BEFORE the
        # max-redirects limit: an explicitly requested stop URL must be honored even
        # when the history is already at the limit.
        stop_at = getattr(session, "redirect_stop_at", None)
        stop_if_contains = getattr(session, "redirect_stop_if_contains", None)

        if stop_at and new_url == stop_at:
            response.history = history
            return None
        if stop_if_contains and stop_if_contains in new_url:
            response.history = history
            return None

        if len(history) >= self.max_redirects:
            raise TooManyRedirectsError(f"Max redirects exceeded (limit: {self.max_redirects})")

        # Append current response to redirect history
        history.append(response)

        # Construct new request payload for next hop in loop
        next_payload = payload.copy()
        if "headers" in payload and isinstance(payload["headers"], dict):
            next_payload["headers"] = payload["headers"].copy()
        next_payload["requestUrl"] = new_url
        next_payload["_redirect_history"] = history

        # Strip credentials when the redirect crosses to a different host, mirroring
        # browser behavior and preventing token/cookie leakage to third parties.
        self._strip_credentials_on_cross_host(session, payload, next_payload, request_url, new_url)

        # RFC 9110 §15.4 method rewriting:
        # - 303 (See Other): turns any method except HEAD into GET and clears body.
        # - 301 & 302: turns POST into GET (preserves PUT, DELETE, PATCH, OPTIONS, etc.).
        # - 307 & 308: preserves the original method and body untouched.
        req_method = str(payload.get("requestMethod", "GET") or "GET").upper()
        next_payload["requestMethod"] = req_method
        if response.status_code == 303:
            if req_method != "HEAD":
                next_payload["requestMethod"] = "GET"
                next_payload["requestBody"] = ""
                next_payload["isByteRequest"] = False
                self._remove_content_headers(next_payload)
        elif response.status_code in (301, 302):
            if req_method == "POST":
                next_payload["requestMethod"] = "GET"
                next_payload["requestBody"] = ""
                next_payload["isByteRequest"] = False
                self._remove_content_headers(next_payload)

        return next_payload

    @staticmethod
    def _remove_content_headers(next_payload: dict[str, Any]) -> None:
        """Removes payload headers that are invalid on a parameterless GET."""
        if "headers" in next_payload and isinstance(next_payload["headers"], dict):
            headers = next_payload["headers"]
            headers_to_remove = [k for k in headers.keys() if k.lower() in ("content-type", "content-length", "transfer-encoding")]
            for k in headers_to_remove:
                headers.pop(k, None)

    @staticmethod
    def _strip_credentials_on_cross_host(
        session, original_payload: dict[str, Any], next_payload: dict[str, Any],
        old_url: str, new_url: str,
    ) -> None:
        old_parsed = urllib.parse.urlsplit(old_url)
        new_parsed = urllib.parse.urlsplit(new_url)
        old_host = (old_parsed.hostname or "").lower()
        new_host = (new_parsed.hostname or "").lower()

        default_ports = {"http": 80, "https": 443}
        old_port = old_parsed.port or default_ports.get(old_parsed.scheme.lower())
        new_port = new_parsed.port or default_ports.get(new_parsed.scheme.lower())

        is_cross_host = bool(not old_host or not new_host or old_host != new_host or old_port != new_port)
        is_scheme_downgrade = bool(old_parsed.scheme.lower() == "https" and new_parsed.scheme.lower() == "http")

        if not (is_cross_host or is_scheme_downgrade):
            return

        logger.debug(
            "Redirect crosses host (%s -> %s) or downgrades scheme (%s -> %s); stripping credential headers.",
            old_host, new_host, old_parsed.scheme, new_parsed.scheme,
        )

        headers = next_payload.get("headers")
        if isinstance(headers, dict):
            for name in [k for k in headers if k.lower() in _CREDENTIAL_HEADERS]:
                headers.pop(name, None)

        # Re-filter injected cookies against the new target host when the session
        # exposes a domain-aware cookie filter (added in 0.1.6).
        if is_scheme_downgrade and next_payload.get("requestCookies"):
            next_payload["requestCookies"] = []
        else:
            cookie_filter = getattr(session, "_filter_request_cookies", None)
            if callable(cookie_filter) and next_payload.get("requestCookies"):
                next_payload["requestCookies"] = cookie_filter(next_payload["requestCookies"], new_url)

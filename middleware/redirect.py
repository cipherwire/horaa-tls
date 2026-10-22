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
        # Save user's original followRedirects preference
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

        # Retrieve/initialize history in active payload
        history: list[Response] = payload.setdefault("_redirect_history", [])
        if len(history) >= self.max_redirects:
            raise TooManyRedirectsError(f"Max redirects exceeded (limit: {self.max_redirects})")

        # Check stop conditions if specified on the session
        stop_at = getattr(session, "redirect_stop_at", None)
        stop_if_contains = getattr(session, "redirect_stop_if_contains", None)

        if stop_at and new_url == stop_at:
            response.history = history
            return None
        if stop_if_contains and stop_if_contains in new_url:
            response.history = history
            return None

        # Append current response to redirect history
        history.append(response)

        # Construct new request payload for next hop in loop
        next_payload = payload.copy()
        next_payload["requestUrl"] = new_url
        next_payload["_redirect_history"] = history

        # Strip credentials when the redirect crosses to a different host, mirroring
        # browser behavior and preventing token/cookie leakage to third parties.
        self._strip_credentials_on_cross_host(session, payload, next_payload, request_url, new_url)

        # For 301, 302, and 303, standard browser behavior converts method to GET and clears body
        if response.status_code in (301, 302, 303):
            next_payload["requestMethod"] = "GET"
            next_payload["requestBody"] = ""
            next_payload["isByteRequest"] = False

            # Remove content headers
            if "headers" in next_payload:
                headers = next_payload["headers"]
                headers_to_remove = [k for k in headers.keys() if k.lower() in ("content-type", "content-length")]
                for k in headers_to_remove:
                    headers.pop(k)

        return next_payload

    @staticmethod
    def _strip_credentials_on_cross_host(
        session, original_payload: dict[str, Any], next_payload: dict[str, Any],
        old_url: str, new_url: str,
    ) -> None:
        old_host = urllib.parse.urlparse(old_url).netloc.lower()
        new_host = urllib.parse.urlparse(new_url).netloc.lower()
        if not old_host or not new_host or old_host == new_host:
            return

        logger.debug("Redirect crosses host (%s -> %s); stripping credential headers.", old_host, new_host)

        headers = next_payload.get("headers")
        if isinstance(headers, dict):
            for name in [k for k in headers if k.lower() in _CREDENTIAL_HEADERS]:
                headers.pop(name, None)

        # Re-filter injected cookies against the new target host when the session
        # exposes a domain-aware cookie filter (added in 0.1.6).
        cookie_filter = getattr(session, "_filter_request_cookies", None)
        if callable(cookie_filter) and next_payload.get("requestCookies"):
            next_payload["requestCookies"] = cookie_filter(next_payload["requestCookies"], new_url)

import asyncio
import base64
import time
import urllib.parse
import uuid
from enum import Enum
from typing import Any

from horaa_tls.backend.ctypes_go import CtypesGoBackend
from horaa_tls.exceptions import BackendError, HoraaTLSError
from horaa_tls.fingerprint.user_agent import UserAgentGenerator
from horaa_tls.log import logger
from horaa_tls.middleware.pipeline import MiddlewarePipeline
from horaa_tls.middleware.proxy import ProxyRotatorMiddleware
from horaa_tls.middleware.redirect import RedirectMiddleware
from horaa_tls.middleware.retry import RetryMiddleware
from horaa_tls.response import Response, build_response


class ClientProfile(str, Enum):
    """Preset browser emulation profiles for Go tls-client library."""
    CHROME_103 = "chrome_103"
    CHROME_110 = "chrome_110"
    CHROME_120 = "chrome_120"
    CHROME_133 = "chrome_133"
    FIREFOX_117 = "firefox_117"
    FIREFOX_123 = "firefox_123"
    FIREFOX_133 = "firefox_133"
    SAFARI_16_0 = "safari_16_0"
    SAFARI_IOS_17_0 = "safari_ios_17_0"
    OPERA_90 = "opera_90"


class Session:
    """
    Session object representing a single TLS connection lifecycle, cookies, and parameters.
    Exposes sync and async APIs.
    """

    def __init__(
        self,
        profile: str | ClientProfile = ClientProfile.CHROME_120,
        proxy: str | None = None,
        proxies: list[str] | None = None,
        proxy_mode: str = "failover",
        header_order: list[str] | None = None,
        pseudo_header_order: list[str] | None = None,
        insecure_skip_verify: bool = False,
        random_tls_extension_order: bool = False,
        use_mitm_when_active: bool = False,
        cookies: dict[str, str] | None = None,
        timeout_seconds: float = 30,
    ):
        """
        Args:
            profile: Browser emulation profile string or ClientProfile enum.
            proxy: Single proxy URL.
            proxies: Explicit list of proxy URLs for rotation.
            proxy_mode: Proxy rotation strategy - 'failover' or 'request'.
            header_order: Custom sequence list of HTTP header keys. Defaults to the
                profile's real browser header order (recommended: leave unset).
            pseudo_header_order: Custom sequence list of HTTP/2 pseudo-header keys (starting with ':').
            insecure_skip_verify: Set to True to bypass SSL certificate verification.
            random_tls_extension_order: Randomize TLS extension order per handshake.
                Off by default: real browsers use a *stable* extension order, and a
                JA3 that changes on every request is itself a bot signal.
            use_mitm_when_active: Set to True to automatically route traffic through
                local Charles/Fiddler proxies if detected active. Off by default so
                production traffic is never silently hijacked by a local dev tool.
            cookies: Initial cookie jar (name -> value).
            timeout_seconds: Default request timeout in seconds.

        Note:
            A Session is NOT thread-safe: cookies and proxy-rotator state are
            mutated per request. Use one Session per thread, or serialize access.
        """
        self.profile = profile.value if isinstance(profile, ClientProfile) else profile
        self.insecure_skip_verify = insecure_skip_verify
        self.random_tls_extension_order = random_tls_extension_order
        self.use_mitm_when_active = use_mitm_when_active

        # Auto-detect local proxy if active and use_mitm_when_active is True
        self.proxy = proxy
        if not self.proxy and self.use_mitm_when_active:
            from horaa_tls.utils.proxy_detector import detect_active_debugging_proxy
            detected = detect_active_debugging_proxy()
            if detected:
                self.proxy = detected

        self.session_id = str(uuid.uuid4())
        self.backend = CtypesGoBackend()

        # Default to the profile's real browser header/pseudo-header order.
        self.header_order = header_order if header_order is not None else \
            UserAgentGenerator.get_header_order_for_profile(self.profile)
        self.pseudo_header_order = pseudo_header_order if pseudo_header_order is not None else \
            UserAgentGenerator.get_pseudo_header_order_for_profile(self.profile)

        # Redirect stop policies (inspected by RedirectMiddleware)
        self.redirect_stop_at: str | None = None
        self.redirect_stop_if_contains: str | None = None

        self.headers = UserAgentGenerator.generate_headers_for_profile(self.profile)
        self.cookies: dict[str, str] = dict(cookies) if cookies else {}
        # Tracks which host set each cookie (cookie name -> host), so cookies
        # received from site A are never replayed to site B.
        self._cookie_domains: dict[str, str] = {}
        self.timeout_seconds: float = float(timeout_seconds)
        self._closed = False

        # Initialize the Pluggable Middleware Subsystem
        self.middleware_pipeline = MiddlewarePipeline()

        # Register Proxy Rotator if proxies/proxy are configured. Registered before
        # RetryMiddleware so that on network/connection errors, failover to a fresh
        # proxy is attempted first instead of burning retry attempts against the
        # same broken proxy (MiddlewarePipeline stops at the first middleware that
        # returns a payload, so registration order is the priority order).
        if proxies or proxy:
            proxy_list = proxies if proxies else [proxy]
            self.proxy_middleware = ProxyRotatorMiddleware(proxies=proxy_list, mode=proxy_mode)
            self.middleware_pipeline.add(self.proxy_middleware)
        else:
            self.proxy_middleware = None

        # Register RetryMiddleware
        self.retry_middleware = RetryMiddleware()
        self.middleware_pipeline.add(self.retry_middleware)

        # Register Redirection Resolver
        self.redirect_middleware = RedirectMiddleware()
        self.middleware_pipeline.add(self.redirect_middleware)

    def _prepare_payload(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        data: str | bytes | dict[str, Any] | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        proxy: str | None = None,
        timeout: int | None = None,
        allow_redirects: bool = True,
        is_byte_response: bool = True,
    ) -> dict[str, Any]:
        """Constructs the JSON request payload expected by the Go shared library FFI."""
        # 1. Format URL with query parameters
        if params:
            url_parts = list(urllib.parse.urlparse(url))
            query = dict(urllib.parse.parse_qsl(url_parts[4]))
            query.update(params)
            url_parts[4] = urllib.parse.urlencode(query)
            url = urllib.parse.urlunparse(url_parts)

        # 2. Merge headers (case-insensitive)
        merged_headers = {k.lower(): v for k, v in self.headers.items()}
        if headers:
            for k, v in headers.items():
                if v is None:
                    merged_headers.pop(k.lower(), None)
                else:
                    merged_headers[k.lower()] = v

        # 3. Format request body
        request_body = ""
        is_byte_request = False
        content_type = None

        if json_data is not None:
            import json
            request_body = json.dumps(json_data)
            content_type = "application/json"
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                request_body = base64.b64encode(data).decode("utf-8")
                is_byte_request = True
            elif isinstance(data, dict):
                request_body = urllib.parse.urlencode(data)
                content_type = "application/x-www-form-urlencoded"
            else:
                request_body = str(data)

        if content_type and "content-type" not in merged_headers:
            merged_headers["content-type"] = content_type

        # 4. Merge cookies (domain-aware: only send cookies valid for this host)
        merged_cookies = self.cookies.copy()
        if cookies:
            merged_cookies.update(cookies)

        target_host = urllib.parse.urlparse(url).netloc.lower()
        request_cookies = []
        for name, value in merged_cookies.items():
            cookie_host = self._cookie_domains.get(name, "")
            if cookie_host and not self._host_matches(cookie_host, target_host):
                continue  # cookie came from a different site - never replay it here
            request_cookies.append(
                {"name": name, "value": value, "domain": "", "path": "/"}
            )

        # 5. Build payload
        payload = {
            "sessionId": self.session_id,
            "tlsClientIdentifier": self.profile,
            "requestMethod": method.upper(),
            "requestUrl": url,
            "requestBody": request_body,
            "isByteRequest": is_byte_request,
            "isByteResponse": is_byte_response,
            "headers": merged_headers,
            "requestCookies": request_cookies,
            "proxyUrl": proxy or self.proxy or "",
            # Go's RequestInput.timeoutSeconds is an int; keep ints as ints
            # (a float like 30.0 fails Go's JSON unmarshalling).
            "timeoutSeconds": int(timeout if timeout is not None else self.timeout_seconds),
            "followRedirects": allow_redirects,
            "insecureSkipVerify": self.insecure_skip_verify,
            "withRandomTLSExtensionOrder": self.random_tls_extension_order,
        }

        # Inject custom header sequence lists if defined on the Session
        if self.header_order:
            payload["headerOrder"] = self.header_order
        if self.pseudo_header_order:
            payload["pseudoHeaderOrder"] = self.pseudo_header_order

        return payload

    @staticmethod
    def _host_matches(cookie_host: str, target_host: str) -> bool:
        """Cookie host matching: exact match, or target is a subdomain of the cookie host."""
        if not cookie_host or not target_host:
            return True
        cookie_host = cookie_host.lstrip(".").lower()
        target_host = target_host.lower()
        return target_host == cookie_host or target_host.endswith("." + cookie_host)

    def _filter_request_cookies(self, cookies: list[dict[str, Any]], url: str) -> list[dict[str, Any]]:
        """Filters an existing requestCookies list against the target URL's host."""
        target_host = urllib.parse.urlparse(url).netloc.lower()
        filtered = []
        for cookie in cookies:
            cookie_host = self._cookie_domains.get(cookie.get("name", ""), "")
            if cookie_host and not self._host_matches(cookie_host, target_host):
                continue
            filtered.append(cookie)
        return filtered

    def _sync_cookies(self, response: Response):
        """Syncs the cookies returned by the request back to the session cookies state,
        remembering which host set each cookie so they are never leaked cross-site."""
        if response.cookies:
            host = urllib.parse.urlparse(response.url).netloc.lower()
            for name, value in response.cookies.items():
                self.cookies[name] = value
                if host:
                    self._cookie_domains[name] = host

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        data: str | bytes | dict[str, Any] | None = None,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        proxy: str | None = None,
        timeout: int | None = None,
        allow_redirects: bool = True,
    ) -> Response:
        """Executes a request synchronously running through the pluggable middleware pipeline."""
        self._ensure_open()
        is_byte_response = True  # Always use byte response to prevent character encoding corruption

        payload = self._prepare_payload(
            method=method,
            url=url,
            params=params,
            data=data,
            json_data=json,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            timeout=timeout,
            allow_redirects=allow_redirects,
            is_byte_response=is_byte_response,
        )

        # Run before_request middleware pipeline hooks
        self.middleware_pipeline.execute_before(self, payload)

        while True:
            try:
                # Execute request via backend FFI
                raw_resp = self.backend.execute(payload)

                if raw_resp.get("status") == 0:
                    raise BackendError(raw_resp.get("body", "Go Request Execution Failed"))

                response = build_response(raw_resp, is_byte_response=is_byte_response)
                self._sync_cookies(response)

                # Run after_response middleware hooks to check for manual redirects or blocks
                next_payload = self.middleware_pipeline.execute_after(self, payload, response)
                if next_payload is not None:
                    delay = next_payload.pop("_retry_delay", None)
                    if delay:
                        time.sleep(delay)
                    payload = next_payload
                    continue

                return response

            except Exception as e:
                # Run after_error middleware hooks to check for retries/proxy failover
                next_payload = self.middleware_pipeline.execute_error(self, payload, e)
                if next_payload is not None:
                    delay = next_payload.pop("_retry_delay", None)
                    if delay:
                        time.sleep(delay)
                    payload = next_payload
                    continue
                # If no middleware handles the error, re-raise it
                raise

    async def request_async(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        data: str | bytes | dict[str, Any] | None = None,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        proxy: str | None = None,
        timeout: int | None = None,
        allow_redirects: bool = True,
    ) -> Response:
        """Executes a request asynchronously running through the pluggable middleware pipeline."""
        self._ensure_open()
        is_byte_response = True

        payload = self._prepare_payload(
            method=method,
            url=url,
            params=params,
            data=data,
            json_data=json,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            timeout=timeout,
            allow_redirects=allow_redirects,
            is_byte_response=is_byte_response,
        )

        # Run before_request middleware pipeline hooks
        self.middleware_pipeline.execute_before(self, payload)

        while True:
            try:
                # Execute request asynchronously via backend FFI
                raw_resp = await self.backend.execute_async(payload)

                if raw_resp.get("status") == 0:
                    raise BackendError(raw_resp.get("body", "Go Request Execution Failed"))

                response = build_response(raw_resp, is_byte_response=is_byte_response)
                self._sync_cookies(response)

                # Run after_response middleware hooks
                next_payload = self.middleware_pipeline.execute_after(self, payload, response)
                if next_payload is not None:
                    delay = next_payload.pop("_retry_delay", None)
                    if delay:
                        await asyncio.sleep(delay)
                    payload = next_payload
                    continue

                return response

            except Exception as e:
                # Run after_error middleware hooks
                next_payload = self.middleware_pipeline.execute_error(self, payload, e)
                if next_payload is not None:
                    delay = next_payload.pop("_retry_delay", None)
                    if delay:
                        await asyncio.sleep(delay)
                    payload = next_payload
                    continue
                raise

    # Helper HTTP method shorthand functions (sync)
    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs) -> Response:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs) -> Response:
        return self.request("PUT", url, data=data, json=json, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs) -> Response:
        return self.request("PATCH", url, data=data, json=json, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    # Shorthand HTTP async method wrappers
    async def get_async(self, url: str, **kwargs) -> Response:
        return await self.request_async("GET", url, **kwargs)

    async def post_async(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs) -> Response:
        return await self.request_async("POST", url, data=data, json=json, **kwargs)

    async def put_async(self, url: str, data: Any | None = None, json: Any | None = None, **kwargs) -> Response:
        return await self.request_async("PUT", url, data=data, json=json, **kwargs)

    async def delete_async(self, url: str, **kwargs) -> Response:
        return await self.request_async("DELETE", url, **kwargs)

    # Lifecycle support
    def _ensure_open(self):
        if self._closed:
            raise HoraaTLSError("Session is closed. Create a new Session to continue.")

    def __enter__(self) -> 'Session':
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    async def __aenter__(self) -> 'Session':
        self._ensure_open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def get_cookies_from_backend(self, url: str) -> list[dict[str, Any]]:
        """Queries the Go memory layer for current active cookies on the specified URL."""
        return self.backend.get_cookies(self.session_id, url)

    def add_cookies_to_backend(self, url: str, cookies: list[dict[str, Any]]):
        """Directly writes cookies to the Go memory layer."""
        self.backend.add_cookies(self.session_id, url, cookies)

    def close(self) -> bool:
        """Destroys the session connection pool and memory on the Go side. Idempotent."""
        if self._closed:
            return True
        self._closed = True
        try:
            return self.backend.destroy_session(self.session_id)
        except Exception as e:
            logger.warning("Failed to destroy session %s: %s", self.session_id, e)
            return False

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the session state into a dictionary.
        """
        data = {
            "profile": self.profile,
            "headers": self.headers,
            "proxy": self.proxy,
            "insecure_skip_verify": self.insecure_skip_verify,
            "random_tls_extension_order": self.random_tls_extension_order,
            "use_mitm_when_active": self.use_mitm_when_active,
            "cookies": self.cookies,
            "cookie_domains": self._cookie_domains,
            "timeout_seconds": self.timeout_seconds,
            "redirect_stop_at": self.redirect_stop_at,
            "redirect_stop_if_contains": self.redirect_stop_if_contains,
            "header_order": self.header_order,
            "pseudo_header_order": self.pseudo_header_order,
            "retry_middleware": {
                "max_retries": self.retry_middleware.max_retries,
                "backoff_factor": self.retry_middleware.backoff_factor,
                "retry_on_status": list(self.retry_middleware.retry_on_status),
                "jitter": self.retry_middleware.jitter,
            },
            "redirect_middleware": {
                "max_redirects": self.redirect_middleware.max_redirects,
            },
        }
        # Include proxy rotator state if present
        if self.proxy_middleware:
            data["proxy_middleware"] = {
                "proxies": self.proxy_middleware.proxies,
                "mode": self.proxy_middleware.mode,
                "max_failovers": self.proxy_middleware.max_failovers,
                "index": self.proxy_middleware._index,
            }
        return data

    def to_json(self) -> str:
        """
        Serializes the session state to a JSON string.
        """
        import json
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Session':
        """
        Recreates a Session instance from a dictionary.
        """
        session = cls(
            profile=data.get("profile", ClientProfile.CHROME_120),
            proxy=data.get("proxy"),
            insecure_skip_verify=data.get("insecure_skip_verify", False),
            use_mitm_when_active=data.get("use_mitm_when_active", False),
            header_order=data.get("header_order"),
            pseudo_header_order=data.get("pseudo_header_order"),
        )
        session.headers = data.get("headers", session.headers)
        session.cookies = data.get("cookies", {})
        session._cookie_domains = data.get("cookie_domains", {})
        session.timeout_seconds = data.get("timeout_seconds", 30)
        session.random_tls_extension_order = data.get("random_tls_extension_order", False)
        session.redirect_stop_at = data.get("redirect_stop_at")
        session.redirect_stop_if_contains = data.get("redirect_stop_if_contains")

        # Restore retry/redirect middleware configurations if they were customized.
        retry_cfg = data.get("retry_middleware") or {}
        if retry_cfg:
            session.retry_middleware.max_retries = retry_cfg.get("max_retries", session.retry_middleware.max_retries)
            session.retry_middleware.backoff_factor = retry_cfg.get("backoff_factor", session.retry_middleware.backoff_factor)
            session.retry_middleware.retry_on_status = tuple(
                retry_cfg.get("retry_on_status", session.retry_middleware.retry_on_status)
            )
            session.retry_middleware.jitter = retry_cfg.get("jitter", session.retry_middleware.jitter)
        redirect_cfg = data.get("redirect_middleware") or {}
        if redirect_cfg:
            session.redirect_middleware.max_redirects = redirect_cfg.get(
                "max_redirects", session.redirect_middleware.max_redirects
            )

        # Reinstate proxy rotator state if present.
        # We construct the middleware directly from the saved data instead of relying
        # on __init__, which may not have created one (e.g. if the original proxy came
        # from MITM auto-detection that is no longer active in this process). This also
        # preserves the full proxy list, mode, and failover limit that were serialized.
        pm_data = data.get("proxy_middleware")
        if pm_data and pm_data.get("proxies"):
            from horaa_tls.middleware.proxy import ProxyRotatorMiddleware
            # If __init__ already registered a proxy middleware, reuse it so we don't
            # end up with two registered in the pipeline.
            if session.proxy_middleware is None:
                session.proxy_middleware = ProxyRotatorMiddleware(
                    proxies=pm_data["proxies"],
                    mode=pm_data.get("mode", "failover"),
                    max_failovers=pm_data.get("max_failovers", 5),
                )
                # Insert at the front so it retains priority over RetryMiddleware,
                # matching the ordering __init__ uses when a proxy is configured
                # up front (failover is tried before burning retry attempts).
                session.middleware_pipeline.insert(0, session.proxy_middleware)
            session.proxy_middleware.proxies = pm_data.get("proxies", [])
            session.proxy_middleware.mode = pm_data.get("mode", "failover")
            session.proxy_middleware.max_failovers = pm_data.get("max_failovers", 5)
            session.proxy_middleware._index = pm_data.get("index", 0)
            # Keep session.proxy in sync with the first proxy in the restored list
            session.proxy = session.proxy_middleware.proxies[0] if session.proxy_middleware.proxies else session.proxy

        return session

    @classmethod
    def from_json(cls, json_str: str) -> 'Session':
        """
        Recreates a Session instance from a JSON string.
        """
        import json
        data = json.loads(json_str)
        return cls.from_dict(data)

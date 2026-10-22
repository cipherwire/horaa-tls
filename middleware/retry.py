import random
from typing import Any

from horaa_tls.exceptions import BackendError, NetworkError, TooManyRedirectsError
from horaa_tls.log import logger
from horaa_tls.middleware.base import BaseMiddleware
from horaa_tls.response import Response


class RetryMiddleware(BaseMiddleware):
    """
    Middleware that intercepts request errors and automatically retries
    failed requests using exponential backoff (with optional jitter).
    """

    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        retry_on_status: tuple[int, ...] = (500, 502, 503, 504),
        jitter: bool = True,
    ):
        """
        Args:
            max_retries: Maximum number of retry attempts.
            backoff_factor: Multiplier for exponential backoff (delay = factor * 2^attempt).
            retry_on_status: HTTP status codes that should trigger a retry.
            jitter: Randomize the backoff delay (0.5x-1.0x) to avoid synchronized
                retry storms across many clients/workers.
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_on_status = retry_on_status
        self.jitter = jitter

    def _compute_delay(self, attempt: int) -> float:
        delay = self.backoff_factor * (2 ** attempt)
        if self.jitter:
            delay *= random.uniform(0.5, 1.0)
        return delay

    def after_response(
        self, session, payload: dict[str, Any], response: Response
    ) -> dict[str, Any] | None:
        # If the response status code is a retryable server error
        if response.status_code in self.retry_on_status:
            attempt = payload.get("_retry_attempt", 0)
            if attempt < self.max_retries:
                delay = self._compute_delay(attempt)
                logger.info(
                    "Server error status %s. Retrying in %.2fs... (Attempt %d/%d)",
                    response.status_code, delay, attempt + 1, self.max_retries,
                )

                next_payload = payload.copy()
                next_payload["_retry_attempt"] = attempt + 1
                # Delay is applied by the caller (sync: time.sleep, async: asyncio.sleep)
                # so the async event loop is never blocked by a synchronous sleep here.
                next_payload["_retry_delay"] = delay
                return next_payload

        return None

    def after_error(
        self, session, payload: dict[str, Any], error: Exception
    ) -> dict[str, Any] | None:
        # A redirect loop is a deterministic failure: re-running the whole chain
        # (max_redirects hops) on every attempt only amplifies the problem.
        if isinstance(error, TooManyRedirectsError):
            return None

        # Only retry on network/connection/backend errors
        if isinstance(error, (NetworkError, BackendError, ConnectionError, TimeoutError)):
            attempt = payload.get("_retry_attempt", 0)
            if attempt < self.max_retries:
                delay = self._compute_delay(attempt)
                logger.info(
                    "Network exception: %s. Retrying in %.2fs... (Attempt %d/%d)",
                    error, delay, attempt + 1, self.max_retries,
                )

                next_payload = payload.copy()
                next_payload["_retry_attempt"] = attempt + 1
                next_payload["_retry_delay"] = delay
                return next_payload

        return None

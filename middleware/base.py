from abc import ABC
from typing import Any

from horaa_tls.response import Response


class BaseMiddleware(ABC):
    """
    Abstract base class for Pluggable Middlewares.
    """

    def before_request(self, session, payload: dict[str, Any]) -> None:
        """
        Called before the request payload is sent to the backend.
        Can modify the payload dict in-place.
        """
        pass

    def after_response(
        self, session, payload: dict[str, Any], response: Response
    ) -> dict[str, Any] | None:
        """
        Called after a response is received from the backend.

        Returns:
            A new payload dictionary to trigger a loop execution, or None to proceed.
        """
        return None

    def after_error(
        self, session, payload: dict[str, Any], error: Exception
    ) -> dict[str, Any] | None:
        """
        Called if an exception is raised during request execution.
        Useful for proxy failover and request retries.

        Returns:
            A new payload dictionary to retry the request, or None to let the error propagate.
        """
        return None

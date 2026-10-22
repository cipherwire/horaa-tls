from typing import Any

from horaa_tls.middleware.base import BaseMiddleware
from horaa_tls.response import Response


class MiddlewarePipeline:
    """
    Manages and runs the sequence of registered middlewares.
    """

    def __init__(self):
        self._middlewares: list[BaseMiddleware] = []

    def add(self, middleware: BaseMiddleware):
        """Appends a middleware instance to the pipeline."""
        self._middlewares.append(middleware)

    def insert(self, index: int, middleware: BaseMiddleware):
        """Inserts a middleware instance at a specific position in the pipeline."""
        self._middlewares.insert(index, middleware)

    def execute_before(self, session, payload: dict[str, Any]) -> None:
        """Runs the before_request hooks in registration order."""
        for middleware in self._middlewares:
            middleware.before_request(session, payload)

    def execute_after(
        self, session, payload: dict[str, Any], response: Response
    ) -> dict[str, Any] | None:
        """
        Runs after_response hooks. If any middleware returns a payload (indicating a retry
        or redirect loop is requested), it is returned immediately.
        """
        for middleware in self._middlewares:
            next_payload = middleware.after_response(session, payload, response)
            if next_payload is not None:
                return next_payload
        return None

    def execute_error(
        self, session, payload: dict[str, Any], error: Exception
    ) -> dict[str, Any] | None:
        """
        Runs after_error hooks when an exception is raised. If any middleware handles the
        error and returns a payload, we retry request using this payload.
        """
        for middleware in self._middlewares:
            next_payload = middleware.after_error(session, payload, error)
            if next_payload is not None:
                return next_payload
        return None

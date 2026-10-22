class HoraaTLSError(Exception):
    """Base exception for horaa-tls."""
    pass


class BackendError(HoraaTLSError):
    """Raised when an error occurs in the pluggable connection backend."""
    pass


class NetworkError(HoraaTLSError):
    """Raised when a network-level error occurs (e.g., timeout, connection failure)."""
    pass


class TooManyRedirectsError(NetworkError):
    """Raised when a redirect chain exceeds the configured maximum.

    Deliberately distinct from :class:`NetworkError` so that
    :class:`horaa_tls.middleware.retry.RetryMiddleware` does not wastefully
    re-run the entire (failing) redirect chain.
    """
    pass

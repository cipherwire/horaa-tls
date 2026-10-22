import os
import socket

from horaa_tls.log import logger


def _port_from_env(env_var: str, default: int) -> int:
    try:
        return int(os.getenv(env_var, default))
    except (TypeError, ValueError):
        return default


# Charles Proxy and Fiddler both default to port 8888. The previous assumption
# of 8889 for Fiddler was incorrect, so it was effectively never detected.
# Override via env vars if your tools listen on non-default ports.
CHARLES_CONFIGURATION: tuple[str, int, float] = (
    "127.0.0.1", _port_from_env("HORAA_TLS_CHARLES_PORT", 8888), 0.01,
)
FIDDLER_CONFIGURATION: tuple[str, int, float] = (
    "127.0.0.1", _port_from_env("HORAA_TLS_FIDDLER_PORT", 8888), 0.01,
)


def is_port_open(host: str, port: int, timeout: float = 0.01) -> bool:
    """Checks if a local port is open by attempting a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


def is_charles_running() -> bool:
    """Checks if Charles Proxy is running on its configured local port."""
    return is_port_open(*CHARLES_CONFIGURATION)


def is_fiddler_running() -> bool:
    """Checks if Fiddler is running on its configured local port."""
    return is_port_open(*FIDDLER_CONFIGURATION)


def detect_active_debugging_proxy() -> str | None:
    """
    Returns proxy URL of the first active debugging proxy detected (Charles or
    Fiddler). Returns None if none are running.
    """
    if is_charles_running():
        logger.debug("Detected local proxy on %s:%d (Charles-compatible).", *CHARLES_CONFIGURATION[:2])
        return f"http://{CHARLES_CONFIGURATION[0]}:{CHARLES_CONFIGURATION[1]}"
    if is_fiddler_running():
        logger.debug("Detected local proxy on %s:%d (Fiddler-compatible).", *FIDDLER_CONFIGURATION[:2])
        return f"http://{FIDDLER_CONFIGURATION[0]}:{FIDDLER_CONFIGURATION[1]}"
    return None

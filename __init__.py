import logging
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

from horaa_tls.client import ClientProfile, Session
from horaa_tls.exceptions import (
    BackendError,
    HoraaTLSError,
    NetworkError,
    TooManyRedirectsError,
)
from horaa_tls.middleware import (
    BaseMiddleware,
    MiddlewarePipeline,
    ProxyRotatorMiddleware,
    RedirectMiddleware,
    RetryMiddleware,
)
from horaa_tls.response import CaseInsensitiveDict, Protocol, Response

try:
    __version__ = _package_version("horaa-tls")
except PackageNotFoundError:  # running from a source checkout
    try:
        import re
        from pathlib import Path
        _pyproj = Path(__file__).resolve().parent / "pyproject.toml"
        _m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', _pyproj.read_text(encoding="utf-8")) if _pyproj.exists() else None
        __version__ = _m.group(1) if _m else "0.2.0"
    except Exception:
        __version__ = "0.2.0"

# Library best practice: never configure handlers, just silence
# "No handlers could be found" noise unless the app opted in.
logging.getLogger("horaa_tls").addHandler(logging.NullHandler())

__all__ = [
    "Session",
    "ClientProfile",
    "Response",
    "CaseInsensitiveDict",
    "Protocol",
    "HoraaTLSError",
    "BackendError",
    "NetworkError",
    "TooManyRedirectsError",
    "BaseMiddleware",
    "MiddlewarePipeline",
    "ProxyRotatorMiddleware",
    "RedirectMiddleware",
    "RetryMiddleware",
    "__version__",
]

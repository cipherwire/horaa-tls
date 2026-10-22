"""FFI backend that bridges Python to the compiled Go tls-client library."""
from horaa_tls.backend.ctypes_go import CtypesGoBackend

__all__ = ["CtypesGoBackend"]

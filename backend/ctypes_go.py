import asyncio
import ctypes
import json
import threading
from typing import Any

from horaa_tls.exceptions import BackendError
from horaa_tls.log import logger
from horaa_tls.utils.updater import update_if_necessary


class CtypesGoBackend:
    """
    Backend implementation that loads the compiled Go tls-client library
    via ctypes and invokes it in-process.
    """

    _lib = None
    _lib_lock = threading.Lock()

    @classmethod
    def get_library(cls):
        """Loads and returns the ctypes Go dynamic library, initializing it on first use (thread-safe)."""
        if cls._lib is None:
            with cls._lib_lock:
                if cls._lib is None:  # double-checked locking
                    try:
                        # Retrieve (and download if needed) the precompiled binary
                        lib_path = update_if_necessary()
                        logger.debug("Loading Go tls-client library from %s", lib_path)
                        lib = ctypes.cdll.LoadLibrary(lib_path)

                        # Define argtypes and restypes for Go-exported C functions
                        lib.request.argtypes = [ctypes.c_char_p]
                        lib.request.restype = ctypes.c_char_p

                        lib.freeMemory.argtypes = [ctypes.c_char_p]
                        lib.freeMemory.restype = ctypes.c_char_p

                        lib.getCookiesFromSession.argtypes = [ctypes.c_char_p]
                        lib.getCookiesFromSession.restype = ctypes.c_char_p

                        lib.addCookiesToSession.argtypes = [ctypes.c_char_p]
                        lib.addCookiesToSession.restype = ctypes.c_char_p

                        lib.destroySession.argtypes = [ctypes.c_char_p]
                        lib.destroySession.restype = ctypes.c_char_p

                        lib.destroyAll.argtypes = []
                        lib.destroyAll.restype = ctypes.c_char_p

                        cls._lib = lib
                    except Exception as e:
                        raise BackendError(f"Failed to load and initialize Go shared library: {e}") from e
        return cls._lib

    def _call(self, response_ptr, error_context: str) -> dict[str, Any] | None:
        """
        Shared response handling for every Go FFI call: decodes the C string pointer,
        parses it as JSON, and always frees the Go-allocated memory afterwards.
        Returns None if the Go library returned a null pointer.
        """
        if not response_ptr:
            return None

        lib = self.get_library()
        # Read the raw C string once up front. We keep a reference to the decoded text
        # so that even when strict JSON parsing fails we can still recover the response
        # "id" and release the Go-allocated buffer instead of leaking it.
        response_obj = None
        response_id = None
        parse_error: Exception | None = None
        try:
            response_bytes = ctypes.string_at(response_ptr)
            decoded = response_bytes.decode("utf-8")
            response_obj = json.loads(decoded)
            if isinstance(response_obj, dict):
                response_id = response_obj.get("id")
        except Exception as e:
            parse_error = e
        finally:
            # Always attempt to release the Go-allocated buffer. When strict parsing
            # failed we still try to recover the "id" field so the free runs on the
            # error path too, rather than skipping it and leaking the buffer.
            if response_id is None:
                response_id = self._recover_response_id(response_ptr)
            if response_id is not None:
                try:
                    lib.freeMemory(response_id.encode("utf-8"))
                except Exception:
                    # Never let a free-time failure mask the original outcome.
                    pass

        if response_obj is None:
            raise BackendError(f"Failed to parse Go response ({error_context}): {parse_error}")
        return response_obj

    @staticmethod
    def _recover_response_id(response_ptr) -> str | None:
        """
        Best-effort extraction of the "id" field from a Go response buffer when strict
        JSON parsing fails. Returns the id string if found, otherwise None.
        """
        try:
            decoded = ctypes.string_at(response_ptr).decode("utf-8", errors="replace")
            marker = '"id"'
            start = decoded.find(marker)
            if start == -1:
                return None
            # Locate the opening quote of the value after the marker.
            colon = decoded.find(":", start)
            if colon == -1:
                return None
            open_quote = decoded.find('"', colon)
            if open_quote == -1:
                return None
            close_quote = decoded.find('"', open_quote + 1)
            if close_quote == -1:
                return None
            return decoded[open_quote + 1:close_quote]
        except Exception:
            return None

    def _execute_sync(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Wrapper around the ctypes C call to request and free memory in Go."""
        lib = self.get_library()
        # Clean request payload by removing private keys starting with '_' (used for Python middleware state)
        clean_payload = {k: v for k, v in request_payload.items() if not k.startswith("_")}
        payload_bytes = json.dumps(clean_payload).encode("utf-8")

        response_ptr = lib.request(payload_bytes)
        response_data = self._call(response_ptr, "request")
        if response_data is None:
            raise BackendError("Null pointer returned from Go request execution.")
        return response_data

    def execute(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Execute request synchronously."""
        return self._execute_sync(request_payload)

    async def execute_async(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Execute request asynchronously by running the blocking ctypes call in an executor."""
        loop = asyncio.get_running_loop()
        # run_in_executor runs the synchronous FFI block in a background thread to prevent GIL stalling
        return await loop.run_in_executor(None, self._execute_sync, request_payload)

    def get_cookies(self, session_id: str, url: str) -> list:
        """Fetch cookies stored in the Go session memory for a given URL."""
        lib = self.get_library()
        payload = json.dumps({"sessionId": session_id, "url": url}).encode("utf-8")
        res_obj = self._call(lib.getCookiesFromSession(payload), "get_cookies")
        return res_obj.get("cookies", []) if res_obj else []

    def add_cookies(self, session_id: str, url: str, cookies: list) -> list:
        """Add cookies into Go session memory for a given URL."""
        lib = self.get_library()
        payload = json.dumps({
            "sessionId": session_id,
            "url": url,
            "cookies": cookies
        }).encode("utf-8")
        res_obj = self._call(lib.addCookiesToSession(payload), "add_cookies")
        return res_obj.get("cookies", []) if res_obj else []

    def destroy_session(self, session_id: str) -> bool:
        """Destroys the session inside Go memory, releasing connections."""
        lib = self.get_library()
        payload = json.dumps({"sessionId": session_id}).encode("utf-8")
        res_obj = self._call(lib.destroySession(payload), "destroy_session")
        return res_obj.get("success", False) if res_obj else False

    def destroy_all_sessions(self) -> bool:
        """Destroys all active sessions inside Go memory."""
        lib = self.get_library()
        res_obj = self._call(lib.destroyAll(), "destroy_all_sessions")
        return res_obj.get("success", False) if res_obj else False

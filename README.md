# 🌌 Horaa TLS
*State-of-the-art in-process browser fingerprint emulation and HTTP client for Python.*

`horaa-tls` is a high-performance HTTP client designed to spoof browser TLS and HTTP/2 characteristics. By interfacing directly with a precompiled Go-based BoringSSL networking backend via a ctypes FFI wrapper, it maintains a footprint indistinguishable from a real web browser to evade fingerprint-based anti-bot detection.

---

## ⚙️ Installation

Install `horaa-tls` directly from PyPI:

```bash
pip install horaa-tls
```

---

## 🛡️ Capabilities & Limitations

*   **What it DOES bypass**: Bypasses passive fingerprinting blocks (such as JA3/JA4 TLS signatures, HTTP/2 frames configuration, and User-Agent/Client Hint alignment) enforced by Cloudflare, Akamai, and Imperva.
*   **What it DOES NOT bypass**: As a socket-level HTTP client, it does not run a browser engine or execute JavaScript. It **cannot** automatically solve interactive browser challenges (like Cloudflare Turnstile checkboxes or JS challenge walls). To access pages protected by active challenges, you must solve them using browser automation (or a solver) and pass the resulting session cookies/tokens to the client.

---

## 💡 Why Horaa TLS?

*   **Zero External Dependencies**: Automatically detects your OS and architecture, downloads the matching precompiled Go libraries, and initializes everything dynamically without requiring third-party pip dependencies.
*   **Supply-Chain Hardened**: The Go library version is pinned, fetched via a direct download URL, and verified against a built-in SHA-256 manifest before it is ever loaded.
*   **Cryptographic Emulation**: Leverages preset browser profiles (Chrome 133, Firefox 133, etc.) to negotiate matching TLS extensions, cipher suites, key share curves, and HTTP/2 settings.
*   **Aligned User-Agents & Client Hints**: Keeps HTTP/2 Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`) perfectly aligned with the selected browser TLS version, and sends each profile's real HTTP header order by default.
*   **Decoupled Middleware Hooks**: Register asynchronous or synchronous middleware layers (such as rotators and retries) directly in the request-response cycle.
*   **Domain-Safe Cookie Jar**: Cookies set by one site are never replayed to another, and `Authorization`/`Cookie` headers are stripped on cross-host redirects.

---

## 🚀 Quick Start (The One-Minute Tour)

Initialize a session mimicking a Chrome 133 browser:

```python
from horaa_tls import Session, ClientProfile

# Context managers close the session (releasing FFI memory) automatically
with Session(profile=ClientProfile.CHROME_133) as session:
    # Perform a request (headers, JA3/JA4, and Client Hints are automatically injected)
    response = session.get("https://httpbingo.org/get")
    print(f"Status Code: {response.status_code}")
    print(response.json())
```

### ⚡ Async Support

Every HTTP method has an async twin (`get_async`, `post_async`, ...) plus a shared
`request_async` entry point. The blocking FFI call runs in a thread executor, so
the event loop is never stalled, and retries back off with `asyncio.sleep`:

```python
import asyncio
from horaa_tls import Session, ClientProfile

async def main():
    async with Session(profile=ClientProfile.CHROME_133) as session:
        r = await session.get_async("https://httpbingo.org/get")
        print(r.status_code)

asyncio.run(main())
```

---

## 📦 Public API (What You Can Import)

Everything below is available directly from the top-level `horaa_tls` package:

```python
from horaa_tls import (
    Session,             # main worker: sends requests, holds cookies/state
    ClientProfile,       # enum of browser profiles to emulate
    Response,            # object returned by requests (.status_code, .json(), .text, .cookies)
    CaseInsensitiveDict, # header container where key case doesn't matter
    Protocol,            # HTTP protocol enum (H1 / HTTP/1.1 / HTTP/2)
    HoraaTLSError,       # base exception for the library
    BackendError,        # raised when the Go FFI layer fails
    NetworkError,        # raised on transport failures / HTTP error status
    TooManyRedirectsError,  # raised when a redirect chain exceeds the limit
    # Middleware authoring:
    BaseMiddleware, MiddlewarePipeline,
    RetryMiddleware, RedirectMiddleware, ProxyRotatorMiddleware,
)
```

| Import | Type | Use it for |
|---|---|---|
| `Session` | class | Creating a session and calling `.get()`, `.post()`, `.head()`, `.request()` |
| `ClientProfile` | enum | Picking which browser to imitate (e.g. `ClientProfile.CHROME_133`) |
| `Response` | class | Reading results: `.status_code`, `.json()`, `.text`, `.headers`, `.cookies` |
| `CaseInsensitiveDict` | class | Accessing headers regardless of capitalization |
| `Protocol` | enum | Checking/negotiating the HTTP version |
| `HoraaTLSError` | exception | Catching any library error in one `except` |
| `BackendError` | exception | Handling failures in the Go shared library |
| `NetworkError` | exception | Handling connection drops and HTTP error responses |
| `TooManyRedirectsError` | exception | Redirect chain exceeded `RedirectMiddleware.max_redirects` |

> **Tip:** you can pass profiles as the enum (`ClientProfile.CHROME_133`) or as a plain string (`"chrome_133"`), both work.

---

## ⚙️ Configuration & Environment Variables

| Environment variable | Purpose |
|---|---|
| `TLS_LIBRARY_PATH` | Use a specific Go shared library file, skipping the updater entirely. |
| `HORAA_TLS_TLS_CLIENT_VERSION` | Pin a different upstream tls-client version (default: `1.16.0`). |
| `HORAA_TLS_CACHE_DIR` | Where the downloaded library is stored (default: `~/.cache/horaa-tls` on Linux/macOS, `%LOCALAPPDATA%\\horaa-tls` on Windows). |
| `HORAA_TLS_CHARLES_PORT` / `HORAA_TLS_FIDDLER_PORT` | Local ports for debugging-proxy detection (default `8888` for both). |
| `GITHUB_TOKEN` / `GH_TOKEN` | Optional; raises GitHub API rate limits when the API fallback path is used. |

Session-level behavior worth knowing:

*   `random_tls_extension_order` (default `False`): real browsers send a stable TLS extension order; randomizing per request changes your JA3 every handshake, which is itself a bot signal. Enable only if you specifically want per-request JA3 rotation.
*   `use_mitm_when_active` (default `False`): opt in to route traffic through a locally running Charles/Fiddler proxy.
*   The Go library download is pinned and SHA-256 verified. A checksum mismatch aborts loading with `BackendError`.

---

## 🛠️ Core Concepts & Advanced Guide

### 🧬 Aligned Browser Profiles
`horaa-tls` currently offers pre-configured emulation profiles:

*   **Chrome Series**: `chrome_103`, `chrome_110`, `chrome_120`, `chrome_133`
*   **Firefox Series**: `firefox_117`, `firefox_123`, `firefox_133`
*   **Safari Series**: `safari_16_0`, `safari_ios_17_0`
*   **Opera Series**: `opera_90`

### 🏗️ Stateful Middleware Pipeline
You can easily intercept, modify, or retry requests using the built-in middleware engine. Registering rotators or exponential backoffs is straightforward:

```python
from horaa_tls import Session, ClientProfile
from horaa_tls.middleware.proxy import ProxyRotatorMiddleware
from horaa_tls.middleware.retry import RetryMiddleware

session = Session(profile=ClientProfile.CHROME_133)

# 1. State-aware proxy rotator with failover recovery
proxies = ["http://proxy1.example.com:8080", "http://proxy2.example.com:8080"]
session.middleware_pipeline.add(
    ProxyRotatorMiddleware(proxies=proxies, mode="failover", max_failovers=3)
)

# 2. Exponential backoff retry handler for transport/network drops
session.middleware_pipeline.add(
    RetryMiddleware(max_retries=3, backoff_factor=2.0, retry_on_status=(500, 502, 503, 504))
)

# Request executes automatically through the middleware pipeline
res = session.get("https://httpbingo.org/get")
session.close()
```

### 📦 Session Snapshots (Persistence)
Export and restore session states (cookies, custom headers, active proxies, and middleware indicators) to distribute scraper instances across servers or queues:

```python
# Save current state
session_state_json = session.to_json()

# Recreate an identical session in a different worker/process
restored_session = Session.from_json(session_state_json)
```

### 🍪 Direct FFI Cookie Management
Interact directly with the Go-layer cookie jar for fine-grained token/session management:

```python
# Read active cookies stored in the Go memory layer
cookies = session.get_cookies_from_backend("https://example.com")

# Inject cookies directly into the Go-layer FFI engine
session.add_cookies_to_backend("https://example.com", [
    {"name": "session_token", "value": "token_value", "domain": ".example.com", "path": "/"}
])
```

---

## Contributing

Pull requests are welcome. If you open one, please describe your changes
properly in the PR description so it's clear what you changed and why.

## Contact

[![Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/QphWRKHvH2)


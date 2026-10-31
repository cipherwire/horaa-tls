<div align="center">

```text
 _                                   _   _     
| |__   ___  _ __ __ _  __ _        | |_| |___ 
| '_ \ / _ \| '__/ _` |/ _` | _____ | __| / __|
| | | | (_) | | | (_| | (_| ||_____|| |_| \__ \
|_| |_|\___/|_|  \__,_|\__,_|        \__|_|___/
```

  <p><strong>High-performance Python HTTP client with native TLS fingerprinting, HTTP/2 framing, and browser impersonation.</strong></p>
  <p>
    <a href="https://github.com/cipherwire/horaa-tls/actions/workflows/ci.yml"><img src="https://github.com/cipherwire/horaa-tls/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
    <a href="https://pypi.org/project/horaa-tls/"><img src="https://img.shields.io/pypi/v/horaa-tls.svg" alt="PyPI Version"></a>
    <a href="https://pypi.org/project/horaa-tls/"><img src="https://img.shields.io/pypi/pyversions/horaa-tls.svg" alt="Python Versions"></a>
    <a href="https://github.com/cipherwire/horaa-tls/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  </p>
</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology & Architecture](#technology--architecture)
- [Platform & Runtime Support](#platform--runtime-support)
- [Installation](#installation)
- [Quickstart: Minimal Working Example](#quickstart-minimal-working-example)
- [Session Management & Request Lifecycle](#session-management--request-lifecycle)
  - [Synchronous Requests](#synchronous-requests)
  - [Asynchronous Requests](#asynchronous-requests)
  - [Resource Management & Context Managers](#resource-management--context-managers)
- [Request Customization](#request-customization)
  - [Query Parameters](#query-parameters)
  - [Form Data & JSON Payloads](#form-data--json-payloads)
  - [Headers & Case-Insensitive Access](#headers--case-insensitive-access)
- [TLS Configuration & Security Defaults](#tls-configuration--security-defaults)
  - [Certificate Verification & Fail-Closed Defaults](#certificate-verification--fail-closed-defaults)
  - [ALPN & Forcing HTTP/1.1](#alpn--forcing-http11)
  - [HTTP/3 (QUIC) & Protocol Racing](#http3-quic--protocol-racing)
  - [Post-Quantum Cryptography (X25519MLKEM768)](#post-quantum-cryptography-x25519mlkem768)
  - [Cached Native Binary SHA-256 Verification](#cached-native-binary-sha-256-verification)
- [Browser Emulation & Client Hints](#browser-emulation--client-hints)
  - [Preset Browser Profiles](#preset-browser-profiles)
  - [HTTP Header & Pseudo-Header Ordering](#http-header--pseudo-header-ordering)
  - [Passive Fingerprinting vs. Active Challenges](#passive-fingerprinting-vs-active-challenges)
- [Redirects, Cookies, Proxies & Retries](#redirects-cookies-proxies--retries)
  - [RFC 9110 Compliant Redirect Policies](#rfc-9110-compliant-redirect-policies)
  - [Origin & Credential Isolation](#origin--credential-isolation)
  - [Cookie Jar Management](#cookie-jar-management)
  - [Proxy Rotation & Failover](#proxy-rotation--failover)
  - [Exponential Backoff Retries](#exponential-backoff-retries)
- [Response Streaming & Large Downloads](#response-streaming--large-downloads)
  - [Direct-to-Disk Streaming](#direct-to-disk-streaming)
  - [Chunk & Line Iterators](#chunk--line-iterators)
- [Public API Reference](#public-api-reference)
- [Environment Variables & Configuration](#environment-variables--configuration)
- [Error Handling](#error-handling)
- [Development, Testing & Release Automation](#development-testing--release-automation)
  - [Running the Test Suite](#running-the-test-suite)
  - [Conventional Commits & Automated Releases](#conventional-commits--automated-releases)
  - [PyPI Trusted Publishing](#pypi-trusted-publishing)
- [Known Limitations & Troubleshooting](#known-limitations--troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`horaa-tls` is an advanced Python HTTP client engineered for passive network fingerprint reproduction and low-level transport control. Standard Python networking libraries (such as `requests`, `urllib3`, and `httpx`) rely on host OpenSSL bindings, producing cryptographic signatures (JA3, JA4, TLS extension sequences) and HTTP/2 framing characteristics that immediately identify them as automated non-browser clients to bot-management platforms (such as Cloudflare, Akamai, and Imperva).

By bridging directly into a precompiled Go-based C-shared library (`bogdanfinn/tls-client` v1.16.0) via `ctypes` FFI, `horaa-tls` synthesizes byte-exact TLS ClientHello packets, HTTP/2 SETTINGS frames, pseudo-header sequences (`:method`, `:authority`, `:scheme`, `:path`), and Client Hints corresponding to modern web browsers.

---

## Key Features

- **Zero External Python Runtime Dependencies:** Pure standard-library Python runtime interface—no third-party dependencies required.
- **Byte-Exact TLS Emulation:** Powered by `bogdanfinn/utls`, reproducing browser-specific cipher suites, extension ordering, supported curves, and GREASE values.
- **Wire-Level HTTP/2 Customization:** Powered by `bogdanfinn/fhttp`, generating browser-faithful SETTINGS sequences and HTTP/2 pseudo-header ordering.
- **Fail-Closed Security Defaults:** Strict TLS X.509 certificate verification enabled by default. Rejects invalid, expired, or self-signed certificates unless explicitly bypassed.
- **Supply-Chain Integrity:** Downloaded native binaries are validated against an immutable SHA-256 manifest before execution. Multi-process concurrency locking prevents install race conditions.
- **RFC 9110 Compliant Redirects:** Implements strict HTTP redirect semantics (method rewriting for 301/302/303, strict method preservation for 307/308, and cross-origin credential isolation).
- **Direct-to-Disk Streaming & Iterators:** Stream large payloads directly to disk without memory overhead, or iterate via `iter_content()` and `iter_lines()`.
- **Synchronous & Asynchronous APIs:** First-class sync interface and non-blocking `asyncio` methods running through a thread executor.
- **Stateful Middleware Architecture:** Built-in extensible middleware pipeline supporting proxy rotation with failover recovery and exponential backoff retries.

---

## Technology & Architecture

| Component | Verified Implementation |
|---|---|
| **Python Interface** | `horaa_tls` high-level package with synchronous and asynchronous (`asyncio`) interfaces |
| **Native Backend** | `bogdanfinn/tls-client` v1.16.0 C-shared library loaded via in-process `ctypes` C-ABI |
| **TLS Implementation** | `bogdanfinn/utls` fork of Go `crypto/tls` with X25519MLKEM768 post-quantum key exchange support |
| **HTTP Protocols** | HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) via browser-aligned protocol racing |
| **Python Compatibility** | Python 3.10, 3.11, 3.12, and 3.13 (confirmed across 150 regression and integration tests) |
| **Operating Systems** | Windows (x86_64, ARM64), Linux (x86_64, ARM64, ARMv7), macOS (Apple Silicon ARM64, Intel x86_64) |
| **Runtime Dependencies** | **0** external Python runtime packages (uses only Python standard library) |
| **Packaging & Standards** | PEP 517 / PEP 621 compliant package build via `setuptools>=61.0.0` and `wheel` |
| **License** | MIT License |

---

## Platform & Runtime Support

`horaa-tls` natively supports the following operating systems and CPU architectures:

| Operating System | Architectures | Shared Library Format |
|---|---|---|
| **Windows** | x86_64 (`amd64`), 32-bit (`386`); ARM64 devices run the `amd64` build under Windows-on-ARM emulation (upstream publishes no `windows-arm64` binary) | `.dll` |
| **Linux (glibc)** | x86_64 (`amd64`), aarch64 (`arm64`), armv7, ppc64le, s390x | `.so` |
| **macOS (Darwin)** | Apple Silicon (`arm64`), Intel 64-bit (`amd64`) | `.dylib` |

> [!NOTE]
> Go C-shared binaries on Linux require standard `glibc`. Alpine Linux and other `musl`-based distributions cannot load Go C-shared libraries via `dlopen()` due to `initial-exec` thread-local storage limitations.

---

## Installation

### Standard Installation (PyPI)

Install the latest release from the Python Package Index:

```bash
pip install horaa-tls
```

### Installation from Source (Development)

Clone the repository and install in editable mode with development dependencies:

```bash
git clone https://github.com/cipherwire/horaa-tls.git
cd horaa-tls
pip install -e .[dev]
```

### Native Binary Resolution & Caching

`horaa-tls` does not require manual compilation of native code. On the first network request:
1. It automatically detects the host operating system and CPU architecture.
2. It fetches the matching precompiled `tls-client` v1.16.0 binary from GitHub Releases.
3. It validates the downloaded file against an immutable SHA-256 hash manifest.
4. It installs the library into a persistent user cache:
   - **Windows:** `%LOCALAPPDATA%\horaa-tls\`
   - **Linux / macOS:** `~/.cache/horaa-tls/`

All subsequent requests load the verified cached library instantly with zero network overhead.

For air-gapped or offline environments, point `TLS_LIBRARY_PATH` directly to a pre-downloaded binary:

```bash
export TLS_LIBRARY_PATH="/opt/binaries/tls-client-xgo-1.16.0-linux-amd64.so"
```

---

## Quickstart: Minimal Working Example

```python
from horaa_tls import Session, ClientProfile

# Initialize a session emulating Google Chrome 120
with Session(profile=ClientProfile.CHROME_120) as session:
    response = session.get("https://httpbin.org/get")
    
    print(f"Status Code: {response.status_code}")
    print(f"HTTP Protocol: {response.protocol}")  # Protocol.HTTP_2
    print("Response JSON:", response.json())
```

---

## Session Management & Request Lifecycle

### Synchronous Requests

The `Session` class manages persistent connection pools, TLS sessions, cookies, and configuration across multiple requests:

```python
from horaa_tls import Session, ClientProfile

session = Session(profile=ClientProfile.CHROME_133, timeout_seconds=15)

try:
    resp1 = session.get("https://httpbin.org/cookies/set?user=alice")
    print("Stored cookies:", session.cookies)

    resp2 = session.get("https://httpbin.org/cookies")
    print("Echoed cookies:", resp2.json())
finally:
    session.close()  # Releases underlying FFI memory
```

### Asynchronous Requests

Every HTTP method provides an asynchronous counterpart (`get_async`, `post_async`, `put_async`, `delete_async`, `patch_async`, `head_async`, `options_async`, `request_async`). Under the hood, blocking FFI execution is dispatched to a non-blocking background thread pool executor:

```python
import asyncio
from horaa_tls import Session, ClientProfile

async def main():
    async with Session(profile=ClientProfile.CHROME_133) as session:
        response = await session.get_async("https://httpbin.org/get")
        print(f"Async Status: {response.status_code}")
        print("Protocol:", response.protocol)

asyncio.run(main())
```

### Resource Management & Context Managers

Using context managers (`with Session() as s:` or `async with Session() as s:`) guarantees that the underlying C-shared library session memory is deallocated promptly when the block exits.

---

## Request Customization

### Query Parameters

`horaa-tls` fully supports dictionaries, lists of tuples, repeated query keys, and existing query strings:

```python
# Repeated keys produce: ?category=books&category=electronics&page=1
params = {
    "category": ["books", "electronics"],
    "page": 1,
}
response = session.get("https://httpbin.org/get", params=params)
```

### Form Data & JSON Payloads

#### JSON Bodies
```python
response = session.post(
    "https://httpbin.org/post",
    json={"username": "agent", "active": True}
)
```

#### Multi-Value Form Encoding
```python
# Automatically sets Content-Type: application/x-www-form-urlencoded
form_data = {
    "filter": ["open", "pending"],
    "limit": "25"
}
response = session.post("https://httpbin.org/post", data=form_data)
```

### Headers & Case-Insensitive Access

Request headers can be passed as standard dictionaries. Response headers are returned in a `CaseInsensitiveDict` supporting both singular and multi-valued lookup:

```python
response = session.get(
    "https://httpbin.org/get",
    headers={"X-Custom-Client": "Horaa"}
)

# Case-insensitive singular lookup
content_type = response.headers.get("content-type")

# Multi-valued header extraction (e.g., multiple Set-Cookie headers)
set_cookies = response.headers.get_list("set-cookie")
```

---

## TLS Configuration & Security Defaults

### Certificate Verification & Fail-Closed Defaults

`horaa-tls` enforces strict TLS certificate verification by default (`insecure_skip_verify=False`). Untrusted, expired, or self-signed certificates fail closed with a `BackendError`:

```python
from horaa_tls import Session, BackendError

session = Session()

try:
    # Fails closed: x509: certificate signed by unknown authority
    session.get("https://self-signed.badssl.com/")
except BackendError as e:
    print(f"Certificate validation failed as expected: {e}")

# Explicit opt-in for testing or debugging environments only:
with Session(insecure_skip_verify=True) as insecure_session:
    resp = insecure_session.get("https://self-signed.badssl.com/")
    assert resp.status_code == 200
```

### ALPN & Forcing HTTP/1.1

By default, modern profiles negotiate HTTP/2 via ALPN. If an endpoint requires HTTP/1.1, set `force_http1=True`:

```python
with Session(force_http1=True) as session:
    response = session.get("https://httpbin.org/get")
    print(response.protocol)  # Protocol.HTTP_1_1
```

### HTTP/3 (QUIC) & Protocol Racing

`horaa-tls` supports real **HTTP/3 over QUIC** via browser-aligned protocol racing. When `with_protocol_racing=True` is enabled, the client launches HTTP/3 (QUIC/UDP) and HTTP/2 (TCP) handshakes concurrently in parallel, settling on whichever protocol completes first:

```python
from horaa_tls import Session, ClientProfile, Protocol

with Session(profile=ClientProfile.CHROME_133, with_protocol_racing=True) as session:
    response = session.get("https://http3.is/")
    print(response.status_code)  # 200
    print(response.protocol)     # Protocol.HTTP_3
```

> [!IMPORTANT]
> **Proxy Leak Prevention:** HTTP/3 transmits data over UDP. Standard HTTP/HTTPS proxies (`http://proxy:8080`) only tunnel TCP and cannot encapsulate UDP traffic. `horaa-tls` enforces strict proxy safety: enabling `with_protocol_racing` alongside a non-SOCKS5 proxy immediately raises a `BackendError` to prevent real IP and DNS leaks. For HTTP/3 traffic through proxies, use `socks5://` or `socks5h://`.

### Post-Quantum Cryptography (X25519MLKEM768)

Modern profiles (such as `chrome_133`) automatically negotiate post-quantum hybrid key exchange (`X25519MLKEM768`) against servers supporting Kyber/ML-KEM, matching the cryptographic handshake of Google Chrome.

### Cached Native Binary SHA-256 Verification

To mitigate local tampering or corrupted binary execution, `horaa-tls` verifies the SHA-256 hash of cached libraries before every execution. Corrupted binaries are refused and raise `BackendError`.

---

## Browser Emulation & Client Hints

### Preset Browser Profiles

The `ClientProfile` enum provides browser emulation presets:

| Category | Profiles |
|---|---|
| **Google Chrome** | `ClientProfile.CHROME_103`, `CHROME_110`, `CHROME_120`, `CHROME_133` |
| **Mozilla Firefox** | `ClientProfile.FIREFOX_117`, `FIREFOX_123`, `FIREFOX_133` |
| **Apple Safari** | `ClientProfile.SAFARI_16_0`, `SAFARI_IOS_17_0` |
| **Opera** | `ClientProfile.OPERA_90` |

Profiles may be passed as enum instances or string identifiers:

```python
session = Session(profile="chrome_133")
```

### HTTP Header & Pseudo-Header Ordering

Real browsers send headers in specific sequences. For example, Chrome transmits HTTP/2 pseudo-headers in the order `:method`, `:authority`, `:scheme`, `:path`, whereas Firefox transmits `:method`, `:path`, `:authority`, `:scheme`. `horaa-tls` automatically applies each profile's authentic header ordering and HTTP/2 SETTINGS frames.

### Passive Fingerprinting vs. Active Challenges

- **What `horaa-tls` handles:** Passive network fingerprinting defenses (JA3/JA4 TLS signatures, extension sequences, cipher suite order, ALPN negotiation, HTTP/2 framing parameters, and Client Hints consistency).
- **What `horaa-tls` does NOT do:** It is a socket-level protocol engine, not a headless browser. It does not execute JavaScript or render DOM elements. Active JavaScript challenges (such as Cloudflare Turnstile or reCAPTCHA v3) must be solved via browser automation or challenge-solving services, with the resulting tokens/cookies passed to `horaa-tls`.

---

## Redirects, Cookies, Proxies & Retries

### RFC 9110 Compliant Redirect Policies

`horaa-tls` implements strict RFC 9110 redirect mechanics:

| Status Code | Semantics | Method Handling | Request Body |
|---|---|---|---|
| **301 Moved Permanently** | Permanent URL change | Rewrites `POST` to `GET`; preserves other methods | Dropped on `POST` -> `GET` rewrite |
| **302 Found** | Temporary URL change | Rewrites `POST` to `GET`; preserves other methods | Dropped on `POST` -> `GET` rewrite |
| **303 See Other** | Explicit redirection to resource | Rewrites **any** method (except `HEAD`) to `GET` | Stripped, along with content headers |
| **307 Temporary Redirect** | Temporary redirect | **Preserves exact method** | Strictly preserved |
| **308 Permanent Redirect** | Permanent redirect | **Preserves exact method** | Strictly preserved |

### Origin & Credential Isolation

When a redirect crosses domains, switches schemes (`https` -> `http`), or changes ports (`:8443` -> `:443`), `horaa-tls` automatically strips sensitive headers:
- `Authorization`
- `Proxy-Authorization`
- Cross-domain `Cookie` headers

### Cookie Jar Management

```python
# Access current session cookies
print(session.cookies)

# Query backend FFI cookie store
cookies = session.get_cookies_from_backend("https://example.com")

# Inject cookies into backend FFI store
session.add_cookies_to_backend("https://example.com", [
    {"name": "session_id", "value": "abc123xyz", "domain": ".example.com", "path": "/"}
])
```

### Proxy Rotation & Failover

```python
from horaa_tls import Session
from horaa_tls.middleware.proxy import ProxyRotatorMiddleware

proxies = [
    "http://user:pass@proxy1.example.com:8080",
    "http://user:pass@proxy2.example.com:8080"
]

session = Session()
# Rotate proxies automatically upon connection failure
session.middleware_pipeline.add(
    ProxyRotatorMiddleware(proxies=proxies, mode="failover", max_failovers=3)
)
```

### Exponential Backoff Retries

```python
from horaa_tls import Session
from horaa_tls.middleware.retry import RetryMiddleware

session = Session()
session.middleware_pipeline.add(
    RetryMiddleware(
        max_retries=3,
        backoff_factor=1.5,
        retry_on_status=(500, 502, 503, 504)
    )
)
```

---

## Response Streaming & Large Downloads

### Direct-to-Disk Streaming

Stream multi-gigabyte files directly to the filesystem without buffering them in memory:

```python
with Session() as session:
    session.get("https://speed.hetzner.de/100MB.bin", download_to="100MB.bin")
```

### Chunk & Line Iterators

Iterate through responses in memory-efficient chunks or line by line:

```python
with Session() as session:
    with session.get("https://httpbin.org/stream/20") as response:
        # Iterate over 4KB chunks
        for chunk in response.iter_content(chunk_size=4096):
            process_chunk(chunk)

        # Or iterate line by line
        for line in response.iter_lines():
            print("Received line:", line.decode("utf-8"))
```

---

## Public API Reference

The top-level `horaa_tls` package exports all core symbols:

```python
from horaa_tls import (
    Session,
    ClientProfile,
    Response,
    CaseInsensitiveDict,
    Protocol,
    HoraaTLSError,
    BackendError,
    NetworkError,
    TooManyRedirectsError,
    BaseMiddleware,
    MiddlewarePipeline,
    RetryMiddleware,
    RedirectMiddleware,
    ProxyRotatorMiddleware,
    __version__,
)
```

---

## Environment Variables & Configuration

| Variable | Default | Description |
|---|---|---|
| `TLS_LIBRARY_PATH` | *Unset* | Explicit path to a native shared library (`.dll`, `.so`, `.dylib`), bypassing updater and cache. |
| `HORAA_TLS_CACHE_DIR` | `%LOCALAPPDATA%\horaa-tls` / `~/.cache/horaa-tls` | Directory where downloaded native libraries and version markers are stored. |
| `HORAA_TLS_TLS_CLIENT_VERSION` | `1.16.0` | Target upstream `bogdanfinn/tls-client` release version. |
| `HORAA_TLS_SKIP_CACHE_VERIFY` | `0` | If set to `1`, skips pre-load SHA-256 hash validation of cached native libraries. |
| `GITHUB_TOKEN` / `GH_TOKEN` | *Unset* | Optional GitHub token to raise API rate limits if the fallback asset resolver is utilized. |

---

## Error Handling

All library exceptions inherit from `HoraaTLSError`:

```python
from horaa_tls import Session, HoraaTLSError, BackendError, NetworkError, TooManyRedirectsError

try:
    with Session() as session:
        response = session.get("https://example.com", timeout_seconds=5)
except TooManyRedirectsError:
    print("Redirect loop encountered!")
except NetworkError as e:
    print(f"Transport/HTTP network failure: {e}")
except BackendError as e:
    print(f"Native Go FFI or TLS error: {e}")
except HoraaTLSError as e:
    print(f"General horaa-tls error: {e}")
```

---

## Development, Testing & Release Automation

### Running the Test Suite

Install dev dependencies and execute the full test suite with `pytest`:

```bash
# Run hermetic unit and regression tests (excluding external network dependencies)
pytest -v -m "not integration"

# Run all tests, including live native TLS integration tests
pytest -v
```

Linting and code style checks:

```bash
ruff check .
```

### Conventional Commits & Automated Releases

This repository adheres to the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `fix:` bumps patch version (e.g. `0.2.0` -> `0.2.1`).
- `feat:` bumps minor version (e.g. `0.2.0` -> `0.3.0`).
- `chore:`, `docs:`, `test:` maintain versioning without releases.

[Release Please](https://github.com/googleapis/release-please) automatically tracks merged commits on `main`, prepares a Release Pull Request updating `CHANGELOG.md` and version metadata, and tags the release when merged.

### PyPI Trusted Publishing

Packages are built and published securely to PyPI via GitHub Actions using **OpenID Connect (OIDC) Trusted Publishing**. No static PyPI API tokens or passwords are used.

---

## Known Limitations & Troubleshooting

1. **Alpine Linux / musl:** Go C-shared binaries use the `initial-exec` thread-local storage (TLS) model, which `musl` libc does not support. Use standard `glibc`-based Linux distributions.
2. **Interactive Challenges:** Cloudflare Turnstile, hCaptcha, and reCAPTCHA checkboxes require JavaScript execution and DOM rendering. Pass session tokens solved via browser automation into `horaa-tls`.
3. **HTTP/3 Protocol Racing:** HTTP/3 racing over HTTP proxies is disabled by default to prevent UDP packet and DNS leakage.

---

## Contributing

Contributions, bug reports, and pull requests are welcome! Please ensure:
1. All changes include corresponding unit tests in `tests/`.
2. All commits follow Conventional Commits formatting (`feat: ...`, `fix: ...`).
3. Code passes `ruff check .` and all `pytest` checks.

---

## License

This project is licensed under the [MIT License](https://github.com/cipherwire/horaa-tls/blob/main/LICENSE).

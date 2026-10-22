# Changelog

## 0.2.0 — 2026-09-05

### Fixed
- **(critical)** Updater generated asset names that no longer exist upstream: bogdanfinn/tls-client
  v1.16.0 renamed all release assets to the `tls-client-xgo-{version}-{os}-{arch}` scheme, which broke
  every fresh install on first request. The updater now understands both the modern and legacy naming
  schemes.
- `CaseInsensitiveDict` was broken as a `dict` subclass: `json.dumps(headers)` returned `{}`,
  equality against plain dicts returned `False`, and `pop()`/`setdefault()` raised `KeyError` on
  existing keys. It now stores data in both the dict and the lowercase lookup map (requests-style)
  and implements case-insensitive equality.
- `Session.close()` is now idempotent and safe against double-close.
- Fiddler detection used port 8889; Fiddler's default port is 8888 (now configurable via
  `HORAA_TLS_FIDDLER_PORT` / `HORAA_TLS_CHARLES_PORT`).
- `timeout=0` (and other falsy values) silently fell back to the session default; explicit
  `timeout` values are now respected (`timeout if timeout is not None else ...`).

### Changed
- **Supply-chain hardening**: the Go library download is now pinned (`1.16.0` by default), fetched
  via a direct download URL (no GitHub API call, no rate limits), and verified against a built-in
  SHA-256 manifest. Override the version with `HORAA_TLS_TLS_CLIENT_VERSION`.
- Downloaded libraries now live in a user-level cache directory (`~/.cache/horaa-tls` on Linux/macOS,
  `%LOCALAPPDATA%\horaa-tls` on Windows, override with `HORAA_TLS_CACHE_DIR`) instead of being
  written into `site-packages` at runtime. Existing in-package `dependencies/` folders from older
  versions keep working. Downloads are atomic (`.tmp` + rename) and protected by a process-wide lock.
- `withRandomTLSExtensionOrder` is now **opt-in** (`Session(random_tls_extension_order=True)`) and
  off by default: real browsers send a *stable* extension order, and per-request JA3 randomization
  is itself a bot signal.
- `use_mitm_when_active` now defaults to `False` so production traffic is never silently routed
  through a local debugging proxy that happens to be running.
- Redirect handling raises `TooManyRedirectsError` (new, subclass of `NetworkError`), which the
  retry middleware no longer retries - previously a redirect loop re-ran the whole chain on every
  retry attempt.
- Cookie jar is domain-aware: cookies received from site A are no longer replayed to site B, and
  `Authorization` / `Cookie` headers are stripped when a redirect crosses to a different host.
- Every browser profile now ships its real HTTP header order and HTTP/2 pseudo-header order by
  default (previously header order was dictionary insertion order, which did not match browsers).
- Library code logs via the `horaa_tls` logger instead of `print()`; a `NullHandler` is installed
  by default.

### Added
- `Session` now supports context managers: `with Session() as s:` / `async with Session() as s:`.
- `Session(random_tls_extension_order=..., cookies=..., timeout_seconds=...)` parameters.
- `Response.ok`, `Response.is_redirect` properties; charset-aware `Response.text` (falls back to
  UTF-8); `Response.json()` tolerates a leading BOM.
- Public exports: `TooManyRedirectsError`, `BaseMiddleware`, `MiddlewarePipeline`,
  `RetryMiddleware`, `RedirectMiddleware`, `ProxyRotatorMiddleware`, `__version__`.
- `__init__.py` files for all subpackages (`backend`, `middleware`, `fingerprint`, `utils`) so the
  package no longer relies on implicit namespace packages.
- Serialization (`to_dict`/`from_dict`) now round-trips cookie domains, the random-TLS-extension
  flag, and retry/redirect middleware configurations.
- Thread-safe lazy loading of the Go library (double-checked locking in `CtypesGoBackend`).
- Test suite (`pytest`) and GitHub Actions CI (3 OS x Python 3.10-3.13), ruff lint config.

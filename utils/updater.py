"""Self-managed downloader for the precompiled Go tls-client shared library.

Resolution order:

1. ``TLS_LIBRARY_PATH`` env var pointing at an existing library file.
2. A previously downloaded library inside the cache directory (tracked by a
   ``.version`` marker file). Cached libraries are trusted and never trigger
   network calls.
3. A direct download of the *pinned* release asset from GitHub (no API call,
   no rate limits, stable URL), verified against a built-in SHA-256 manifest.
4. Fallback: query the GitHub releases API (pinned tag first, then latest) and
   fuzzy-match an asset for the current platform.

Downloaded libraries live in a user-level cache directory (never inside
``site-packages``, which may be read-only):

- Linux/other: ``$XDG_CACHE_HOME/horaa-tls`` (default ``~/.cache/horaa-tls``)
- macOS:       ``~/.cache/horaa-tls``
- Windows:     ``%LOCALAPPDATA%/horaa-tls``

Override with the ``HORAA_TLS_CACHE_DIR`` env var. For backward compatibility,
an existing ``dependencies/`` folder inside the installed package (created by
horaa-tls <= 0.1.5) keeps being used when present.
"""
import ctypes
import hashlib
import json
import os
import platform
import sys
import threading
import urllib.request

from horaa_tls.exceptions import BackendError
from horaa_tls.log import logger

OWNER = "bogdanfinn"
REPO = "tls-client"

# Default pinned upstream version. Pinning means upstream release-asset renames
# (like the v1.16.0 "xgo" rebrand) can never break installed users, and lets us
# ship a verified SHA-256 manifest for supply-chain safety. Override freely:
#   HORAA_TLS_TLS_CLIENT_VERSION=1.15.0
DEFAULT_TLS_CLIENT_VERSION = "1.16.0"

RELEASES_API_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/releases"
RELEASE_TAG_API_URL = RELEASES_API_URL + "/tags/v{version}"
RELEASE_DOWNLOAD_URL = f"https://github.com/{OWNER}/{REPO}/releases/download/v{{version}}/{{asset}}"

# SHA-256 manifest for DEFAULT_TLS_CLIENT_VERSION. Assets downloaded from the
# direct URL are verified against this table; unknown assets (e.g. custom
# versions) skip verification with a warning.
ASSET_SHA256: dict = {
    "tls-client-xgo-1.16.0-darwin-amd64.dylib": "9cb5fd24bceb74cedd4372bdbdf013058c650fa6f8df2a1336918d8ee54128d8",
    "tls-client-xgo-1.16.0-darwin-arm64.dylib": "f3a6f5ffadc4a7f5184d9880380e522fbaf6890c623eae1ac0805071f42f5aaa",
    "tls-client-xgo-1.16.0-linux-386.so": "5ea81308e53e236dae73b35bd4a09af1201191c32713ea2968b85bbcfe94b616",
    "tls-client-xgo-1.16.0-linux-amd64.so": "75f19133e3cb9b16ab3d2dfe3376c7590aab2fe6f2294debac661bfd63dca6a3",
    "tls-client-xgo-1.16.0-linux-arm-5.so": "02cca934f2fc15db658e2d94ed472691224656b696c6531ffec2d0aad2997b2f",
    "tls-client-xgo-1.16.0-linux-arm-6.so": "5c991eca511de6d0ea04f12100c89a7750696213e246226e4050d88bf7e9136b",
    "tls-client-xgo-1.16.0-linux-arm-7.so": "ee9125b4580bf3e1515304e6faeb4ce30eb88f47c5158349a14d38b25448c358",
    "tls-client-xgo-1.16.0-linux-arm64.so": "91f88d35fa64284c811373003d2a26caa3145eaeefd1c0e9576f10724a914332",
    "tls-client-xgo-1.16.0-linux-ppc64le.so": "df58659941d9a2804766115a48028eaaabfc62f13622c6b5f9c2031786f745f9",
    "tls-client-xgo-1.16.0-linux-riscv64.so": "29530a9137f95f969639a7658fcb87ebd6a05e2073cd41410499d48326b51b33",
    "tls-client-xgo-1.16.0-linux-s390x.so": "5c312925c22c145b05de8d3ee86f345484a5b9a314d0f40cd0c034a11baee182",
    "tls-client-xgo-1.16.0-windows-386.dll": "f41099111446ec3252166b640156a2213d387511e4e80e849ce8b8a0871be47f",
    "tls-client-xgo-1.16.0-windows-amd64.dll": "33d9b5a4a1a902bae57494186ddce91af32fb67326d94ea04776447a81c15934",
}

# Serializes downloads/library resolution across threads and sessions.
_update_lock = threading.Lock()

_HTTP_TIMEOUT = 30
_DOWNLOAD_TIMEOUT = 300


# ---------------------------------------------------------------------------
# Platform / asset naming
# ---------------------------------------------------------------------------

def get_root_dir() -> str:
    """Returns the absolute root directory of the package."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_dependencies_dir() -> str:
    """Returns the cache directory where shared libraries are stored."""
    env_dir = os.getenv("HORAA_TLS_CACHE_DIR")
    if env_dir:
        deps_dir = os.path.abspath(env_dir)
        os.makedirs(deps_dir, exist_ok=True)
        return deps_dir

    # Backward compatibility: keep using the legacy in-package folder when a
    # previous install already populated it (horaa-tls <= 0.1.5).
    legacy_dir = os.path.join(get_root_dir(), "dependencies")
    if os.path.exists(os.path.join(legacy_dir, ".version")):
        return legacy_dir

    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        deps_dir = os.path.join(base, "horaa-tls")
    else:
        xdg = os.getenv("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
        deps_dir = os.path.join(xdg, "horaa-tls")

    os.makedirs(deps_dir, exist_ok=True)
    return deps_dir


def get_system_platform() -> tuple[str, str]:
    """
    Returns (system_os, architecture) using the modern upstream naming:
      system_os:   'darwin' | 'windows' | 'linux'
      architecture: 'amd64' | 'arm64' | '386' | 'arm-5' | 'arm-6' | 'arm-7'
    """
    system_os = platform.system().lower()
    machine = platform.machine().lower()

    if system_os == "darwin":
        return "darwin", ("arm64" if machine == "arm64" else "amd64")

    if system_os in ("windows", "win32", "cygwin"):
        return "windows", ("amd64" if ctypes.sizeof(ctypes.c_voidp) == 8 else "386")

    sys_os = "linux"
    if machine in ("aarch64", "arm64"):
        return sys_os, "arm64"
    if machine in ("x86_64", "amd64"):
        return sys_os, "amd64"
    if machine in ("i386", "i486", "i586", "i686", "x86"):
        return sys_os, "386"
    if machine.startswith("armv5"):
        return sys_os, "arm-5"
    if machine.startswith("armv6"):
        return sys_os, "arm-6"
    if machine.startswith("armv7"):
        return sys_os, "arm-7"
    # Unknown architectures fall back to amd64 (most common host platform).
    return sys_os, "amd64"


def generate_asset_names(version: str) -> list[str]:
    """
    Returns candidate asset filenames for the current platform, modern first.

    Modern scheme (>= v1.16.0):  tls-client-xgo-1.16.0-linux-amd64.so
    Legacy scheme  (< v1.16.0):  tls-client-linux-ubuntu-amd64-1.7.8.so
    """
    sys_os, arch = get_system_platform()

    if sys_os == "windows":
        ext = ".dll"
    elif sys_os == "darwin":
        ext = ".dylib"
    else:
        ext = ".so"

    modern = f"tls-client-xgo-{version}-{sys_os}-{arch}{ext}"

    # Legacy names are only used to recognize caches created by older
    # horaa-tls versions; upstream no longer publishes them.
    legacy_arch = arch
    if sys_os == "windows":
        legacy_arch = "64" if arch == "amd64" else "32"
    legacy_os = sys_os
    if sys_os == "linux":
        legacy_os = "linux-alpine" if os.path.exists("/etc/alpine-release") else "linux-ubuntu"
    legacy = f"tls-client-{legacy_os}-{legacy_arch}-{version}{ext}"

    return [modern, legacy]


# Kept for backward compatibility with code importing the old singular helper.
def generate_asset_name(version: str) -> str:
    """Returns the primary (modern) asset filename for the current platform."""
    return generate_asset_names(version)[0]


# ---------------------------------------------------------------------------
# Version marker files
# ---------------------------------------------------------------------------

def read_local_version() -> tuple[str | None, str | None]:
    """Reads current local shared lib asset name and version from .version file."""
    deps_dir = get_dependencies_dir()
    version_file = os.path.join(deps_dir, ".version")
    if not os.path.exists(version_file):
        return None, None
    try:
        with open(version_file) as f:
            content = f.read().strip().split(" ")
            if len(content) == 2:
                return content[0], content[1]
    except Exception:
        pass
    return None, None


def save_local_version(asset_name: str, version: str):
    """Saves the local asset name and version to the .version file."""
    deps_dir = get_dependencies_dir()
    version_file = os.path.join(deps_dir, ".version")
    with open(version_file, "w") as f:
        f.write(f"{asset_name} {version}")


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int) -> urllib.request.Request:
    headers = {"User-Agent": "horaa-tls-updater", "Accept": "application/octet-stream"}
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"token {token}"
    return urllib.request.Request(url, headers=headers)


def download_asset(url: str, dest_path: str, expected_sha256: str | None = None):
    """Streams the file from ``url`` to ``dest_path`` atomically, verifying SHA-256 when known."""
    tmp_path = dest_path + ".tmp"
    hasher = hashlib.sha256()
    try:
        with urllib.request.urlopen(_http_get(url, _DOWNLOAD_TIMEOUT), timeout=_DOWNLOAD_TIMEOUT) as response, open(tmp_path, "wb") as out_file:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                out_file.write(chunk)
        if expected_sha256 and hasher.hexdigest().lower() != expected_sha256.lower():
            raise BackendError(
                f"SHA-256 mismatch for downloaded library (expected {expected_sha256}, got {hasher.hexdigest()}). "
                "Refusing to load a potentially tampered binary."
            )
        os.replace(tmp_path, dest_path)  # atomic on POSIX and Windows
    except BackendError:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise BackendError(f"Failed to download asset: {e}") from e


def _cleanup_old_libraries(deps_dir: str, keep_asset: str):
    """Removes stale libraries in the cache folder, keeping the active one."""
    for file in os.listdir(deps_dir):
        if file in (keep_asset, ".version") or file.startswith("."):
            continue
        try:
            os.remove(os.path.join(deps_dir, file))
        except OSError:
            pass


def _install_from_url(url: str, deps_dir: str, asset_name: str, version: str) -> str:
    target_path = os.path.join(deps_dir, asset_name)
    logger.info("Downloading Go tls-client library %s ...", asset_name)
    download_asset(url, target_path, expected_sha256=ASSET_SHA256.get(asset_name))
    save_local_version(asset_name, version)
    _cleanup_old_libraries(deps_dir, asset_name)
    return target_path


def _fetch_release_payload(version: str | None) -> dict:
    """Fetches a release payload from the GitHub API (pinned tag first, then latest)."""
    urls = []
    if version:
        urls.append(RELEASE_TAG_API_URL.format(version=version))
    urls.append(RELEASES_API_URL + "/latest")

    last_error: Exception | None = None
    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "horaa-tls-updater",
                    "Accept": "application/vnd.github.v3+json",
                    **({"Authorization": f"token {t}"} if (t := os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")) else {}),
                },
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as e:
            last_error = e
    raise BackendError(f"Failed to fetch release info from GitHub: {last_error}")


def _resolve_via_api(deps_dir: str, version: str, candidate_names: list[str]) -> str:
    """Last-resort resolution: ask the GitHub API and fuzzy-match a platform asset."""
    data = _fetch_release_payload(version)
    assets = data.get("assets", []) if isinstance(data, dict) else []
    tag = str(data.get("tag_name", "")).lstrip("v") if isinstance(data, dict) else version

    sys_os, arch = get_system_platform()
    download_url = None
    asset_name = None

    # Exact candidates first, then a substring fuzzy match on os+arch.
    for name in candidate_names:
        for asset in assets:
            if asset["name"] == name:
                download_url, asset_name = asset["browser_download_url"], asset["name"]
                break
        if download_url:
            break
    if not download_url:
        for asset in assets:
            name = asset["name"]
            if f"{sys_os}-{arch}" in name and tag in name and name.endswith((".so", ".dll", ".dylib")):
                download_url, asset_name = asset["browser_download_url"], name
                break

    if not download_url:
        raise BackendError(
            f"No suitable tls-client asset found for platform '{sys_os}-{arch}' in release v{tag}."
        )
    return _install_from_url(download_url, deps_dir, asset_name, tag)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def update_if_necessary() -> str:
    """
    Checks if the shared library needs downloading or updating, and returns the
    path to the loadable library file. Thread-safe; never hits the network when
    a cached library is present.
    """
    # 1. Manual environment override always wins.
    env_path = os.getenv("TLS_LIBRARY_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    with _update_lock:
        return _update_locked()


def _update_locked() -> str:
    deps_dir = get_dependencies_dir()

    # 2. Trust the cache marker: no network calls for repeat sessions.
    local_asset, _local_version = read_local_version()
    if local_asset and os.path.exists(os.path.join(deps_dir, local_asset)):
        return os.path.join(deps_dir, local_asset)

    version = os.getenv("HORAA_TLS_TLS_CLIENT_VERSION") or DEFAULT_TLS_CLIENT_VERSION
    candidate_names = generate_asset_names(version)

    # 3. Tolerate a library file that exists but lost its .version marker.
    for name in candidate_names:
        path = os.path.join(deps_dir, name)
        if os.path.exists(path):
            save_local_version(name, version)
            return path

    # 4. Direct pinned download: no GitHub API, no rate limits, checksum verified.
    primary = candidate_names[0]
    direct_url = RELEASE_DOWNLOAD_URL.format(version=version, asset=primary)
    try:
        return _install_from_url(direct_url, deps_dir, primary, version)
    except BackendError as e:
        logger.warning("Direct download of %s failed (%s); falling back to GitHub API.", primary, e)

    # 5. Fallback: resolve through the releases API (handles renamed assets,
    #    unpinned custom versions, and legacy naming).
    return _resolve_via_api(deps_dir, version, candidate_names)

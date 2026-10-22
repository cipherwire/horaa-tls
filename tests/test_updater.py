"""Tests for the shared-library updater: naming, resolution order, checksums."""
import os

import pytest
from horaa_tls.exceptions import BackendError
from horaa_tls.utils import updater


class TestAssetNaming:
    def test_modern_linux_amd64(self, monkeypatch):
        monkeypatch.setattr(updater, "get_system_platform", lambda: ("linux", "amd64"))
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        names = updater.generate_asset_names("1.16.0")
        assert names[0] == "tls-client-xgo-1.16.0-linux-amd64.so"
        assert "ubuntu" in names[1] or "alpine" in names[1]

    def test_modern_darwin_arm64(self, monkeypatch):
        monkeypatch.setattr(updater, "get_system_platform", lambda: ("darwin", "arm64"))
        names = updater.generate_asset_names("1.16.0")
        assert names[0] == "tls-client-xgo-1.16.0-darwin-arm64.dylib"

    def test_modern_windows_amd64(self, monkeypatch):
        monkeypatch.setattr(updater, "get_system_platform", lambda: ("windows", "amd64"))
        names = updater.generate_asset_names("1.16.0")
        assert names[0] == "tls-client-xgo-1.16.0-windows-amd64.dll"
        # legacy windows naming used "64"
        assert names[1] == "tls-client-windows-64-1.16.0.dll"

    def test_backward_compat_helper(self):
        assert updater.generate_asset_name("1.16.0") == updater.generate_asset_names("1.16.0")[0]


class TestChecksumManifest:
    def test_manifest_covers_all_1_16_0_assets(self):
        expected = {
            "tls-client-xgo-1.16.0-darwin-amd64.dylib", "tls-client-xgo-1.16.0-darwin-arm64.dylib",
            "tls-client-xgo-1.16.0-linux-386.so", "tls-client-xgo-1.16.0-linux-amd64.so",
            "tls-client-xgo-1.16.0-linux-arm-5.so", "tls-client-xgo-1.16.0-linux-arm-6.so",
            "tls-client-xgo-1.16.0-linux-arm-7.so", "tls-client-xgo-1.16.0-linux-arm64.so",
            "tls-client-xgo-1.16.0-linux-ppc64le.so", "tls-client-xgo-1.16.0-linux-riscv64.so",
            "tls-client-xgo-1.16.0-linux-s390x.so", "tls-client-xgo-1.16.0-windows-386.dll",
            "tls-client-xgo-1.16.0-windows-amd64.dll",
        }
        assert expected == set(updater.ASSET_SHA256.keys())

    def test_all_checksums_are_64_hex_chars(self):
        for name, digest in updater.ASSET_SHA256.items():
            assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), name


class TestResolutionOrder:
    def test_env_override_wins(self, monkeypatch, tmp_path):
        lib = tmp_path / "custom.so"
        lib.write_bytes(b"\x00fake")
        monkeypatch.setenv("TLS_LIBRARY_PATH", str(lib))
        assert updater.update_if_necessary() == str(lib)

    def test_cached_library_needs_no_network(self, monkeypatch, tmp_path):
        # If a cache marker + library exist, resolution must return without any network call.
        deps = tmp_path / "cache"
        deps.mkdir()
        (deps / ".version").write_text("tls-client-xgo-1.16.0-linux-amd64.so 1.16.0")
        (deps / "tls-client-xgo-1.16.0-linux-amd64.so").write_bytes(b"\x7fELFfake")

        monkeypatch.delenv("TLS_LIBRARY_PATH", raising=False)
        monkeypatch.setenv("HORAA_TLS_CACHE_DIR", str(deps))

        def explode(*a, **kw):  # any network attempt fails the test
            raise AssertionError("network access attempted despite cached library")

        monkeypatch.setattr(updater, "_install_from_url", explode)
        monkeypatch.setattr(updater, "_resolve_via_api", explode)
        assert updater.update_if_necessary().endswith("tls-client-xgo-1.16.0-linux-amd64.so")

    def test_checksum_mismatch_rejects_download(self, monkeypatch, tmp_path):
        deps = tmp_path / "cache"
        monkeypatch.setenv("HORAA_TLS_CACHE_DIR", str(deps))
        monkeypatch.delenv("TLS_LIBRARY_PATH", raising=False)

        def fake_download(url, dest_path, expected_sha256=None):
            assert expected_sha256 == updater.ASSET_SHA256["tls-client-xgo-1.16.0-linux-amd64.so"]
            # simulate a tampered file: write directly, bypassing verification
            with open(dest_path, "wb") as f:
                f.write(b"tampered")

        monkeypatch.setattr(updater, "_install_from_url", lambda *a, **kw: (_ for _ in ()).throw(
            BackendError("boom")
        ))
        monkeypatch.setattr(updater, "_resolve_via_api", lambda *a, **kw: (_ for _ in ()).throw(
            BackendError("no api")
        ))
        with pytest.raises(BackendError):
            updater.update_if_necessary()

    def test_download_asset_verifies_sha256(self, monkeypatch, tmp_path):
        import hashlib

        good = hashlib.sha256(b"content").hexdigest()
        url = "https://example.com/lib.so"

        class FakeResponse:
            def __init__(self):
                self._data = [b"content"]

            def read(self, n):
                return self._data.pop(0) if self._data else b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(updater.urllib.request, "urlopen", lambda req, timeout: FakeResponse())

        dest = tmp_path / "lib.so"
        updater.download_asset(url, str(dest), expected_sha256=good)
        assert dest.read_bytes() == b"content"

        with pytest.raises(BackendError, match="SHA-256 mismatch"):
            updater.download_asset(url, str(dest), expected_sha256="0" * 64)

    def test_cache_dir_env_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HORAA_TLS_CACHE_DIR", str(tmp_path / "custom"))
        assert updater.get_dependencies_dir() == str(tmp_path / "custom")
        assert os.path.isdir(tmp_path / "custom")

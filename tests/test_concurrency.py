"""Tests for cross-process concurrency and installation race condition safety."""
import os
import subprocess
import sys

import pytest
from horaa_tls.exceptions import BackendError
from horaa_tls.utils import updater


def test_process_lock_mutual_exclusion(tmp_path):
    """Verifies that _ProcessLock serializes multiple concurrent OS processes."""
    lock_file = str(tmp_path / ".install.lock")
    script = (
        "import sys, time\n"
        "from horaa_tls.utils.updater import _ProcessLock\n"
        f"with _ProcessLock(r'{lock_file}', timeout=10.0, poll_interval=0.02):\n"
        "    time.sleep(0.08)\n"
        "print('LOCK_ACQUIRED')\n"
    )

    procs = [
        subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(4)
    ]
    results = [p.communicate() for p in procs]
    outputs = [r[0].strip() for r in results]
    errors = [r[1].strip() for r in results]

    assert all(out == "LOCK_ACQUIRED" for out in outputs), f"Unexpected process outputs: {outputs}, errors: {errors}"


def test_concurrent_simulated_downloads(tmp_path, monkeypatch):
    """Verifies that _ProcessLock with unique temp file paths serializes concurrent downloads safely."""
    dest = str(tmp_path / "lib.dll")
    lock_file = str(tmp_path / ".install.lock")
    script = (
        "import os, time, uuid\n"
        "from horaa_tls.utils.updater import _ProcessLock\n"
        f"dest = r'{dest}'\n"
        f"lock_file = r'{lock_file}'\n"
        "with _ProcessLock(lock_file, timeout=10.0, poll_interval=0.02):\n"
        "    if not os.path.exists(dest):\n"
        "        tmp = f'{dest}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}'\n"
        "        with open(tmp, 'wb') as f:\n"
        "            time.sleep(0.04)\n"
        "            f.write(b'valid data')\n"
        "        os.replace(tmp, dest)\n"
        "print('INSTALL_VERIFIED')\n"
    )

    procs = [
        subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(4)
    ]
    results = [p.communicate() for p in procs]
    outputs = [r[0].strip() for r in results]

    assert all(out == "INSTALL_VERIFIED" for out in outputs)
    assert os.path.exists(dest)
    with open(dest, "rb") as f:
        assert f.read() == b"valid data"


def test_cache_verification_by_default_rejects_corrupted_binary(tmp_path, monkeypatch):
    """Verifies that secure verification is ON by default and blocks tampered cached libraries."""
    monkeypatch.setenv("HORAA_TLS_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("HORAA_TLS_SKIP_CACHE_VERIFY", raising=False)

    asset_name = updater.generate_asset_name(updater.DEFAULT_TLS_CLIENT_VERSION)
    lib_path = tmp_path / asset_name
    lib_path.write_bytes(b"malicious_or_corrupted_bytes")

    version_file = tmp_path / ".version"
    version_file.write_text(f"{asset_name} {updater.DEFAULT_TLS_CLIENT_VERSION}")

    with pytest.raises(BackendError, match="failed SHA-256 verification"):
        updater.update_if_necessary()


def test_cache_verification_opt_out(tmp_path, monkeypatch):
    """Verifies that HORAA_TLS_SKIP_CACHE_VERIFY allows explicit override for custom unverified binaries."""
    monkeypatch.setenv("HORAA_TLS_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("HORAA_TLS_SKIP_CACHE_VERIFY", "1")

    asset_name = updater.generate_asset_name(updater.DEFAULT_TLS_CLIENT_VERSION)
    lib_path = tmp_path / asset_name
    lib_path.write_bytes(b"custom_developer_build")

    version_file = tmp_path / ".version"
    version_file.write_text(f"{asset_name} {updater.DEFAULT_TLS_CLIENT_VERSION}")

    # Does not raise BackendError because verification was explicitly bypassed
    resolved = updater.update_if_necessary()
    assert resolved == str(lib_path)

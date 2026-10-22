import json
import re
from pathlib import Path

import horaa_tls

ROOT = Path(__file__).resolve().parent.parent


def test_version_consistency_across_metadata():
    """Verify that pyproject.toml, horaa_tls.__version__, and .release-please-manifest.json are synchronized."""
    # 1. Read pyproject.toml
    pyproject_path = ROOT / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml missing"
    pyproj_text = pyproject_path.read_text(encoding="utf-8")
    m_pyproj = re.search(r'version\s*=\s*["\']([^"\']+)["\']', pyproj_text)
    assert m_pyproj, "Version declaration not found in pyproject.toml"
    pyproj_version = m_pyproj.group(1)

    # 2. Read .release-please-manifest.json
    manifest_path = ROOT / ".release-please-manifest.json"
    assert manifest_path.exists(), ".release-please-manifest.json missing"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_version = manifest_data.get(".")
    assert manifest_version, "Version missing in .release-please-manifest.json"

    # Assertions
    assert (
        pyproj_version == manifest_version
    ), f"pyproject.toml version ({pyproj_version}) does not match .release-please-manifest.json ({manifest_version})"
    assert (
        horaa_tls.__version__ == pyproj_version
    ), f"horaa_tls.__version__ ({horaa_tls.__version__}) does not match pyproject.toml ({pyproj_version})"

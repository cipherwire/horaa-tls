import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_version_consistency_across_metadata():
    """Verify that pyproject.toml, __init__.py fallback, and .release-please-manifest.json are synchronized."""
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

    # 3. Read __init__.py fallback
    init_path = ROOT / "__init__.py"
    assert init_path.exists(), "__init__.py missing"
    init_text = init_path.read_text(encoding="utf-8")
    m_init = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_text)
    assert m_init, "__version__ fallback not found in __init__.py"
    init_version = m_init.group(1)

    # Assertions
    assert (
        pyproj_version == manifest_version
    ), f"pyproject.toml version ({pyproj_version}) does not match .release-please-manifest.json ({manifest_version})"
    assert (
        pyproj_version == init_version
    ), f"pyproject.toml version ({pyproj_version}) does not match __init__.py fallback ({init_version})"

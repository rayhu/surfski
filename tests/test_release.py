"""Versioning and release tooling (#11)."""

import importlib.util
import subprocess
import sys
import tomllib
from importlib import metadata
from pathlib import Path

import pytest
from fastmcp import Client

import surfski.version as ver
from surfski import cli
from surfski.audit import redact
from surfski.metrics import Metrics
from surfski.server import create_app

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def load_script():
    spec = importlib.util.spec_from_file_location("changelog_section", ROOT / "scripts" / "changelog_section.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- version


def test_version_matches_pyproject():
    assert ver.__version__ == PYPROJECT_VERSION == metadata.version("surfski")


def test_version_fallback_for_source_checkout(monkeypatch):
    def missing(name):
        raise metadata.PackageNotFoundError(name)
    monkeypatch.setattr(ver.metadata, "version", missing)
    assert ver.get_version() == ver.UNKNOWN


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"surfski {PYPROJECT_VERSION}"


async def test_server_info_and_metrics_use_the_version(config, storage):
    app = create_app(config, storage=storage, with_auth=False)
    async with Client(app) as c:
        assert c.server_info.version == PYPROJECT_VERSION
    assert f'surfski_build_info{{version="{PYPROJECT_VERSION}"}} 1' in Metrics().render(0, 0)


# ---------------------------------------------------------------- changelog


CHANGELOG = """# Changelog

## [Unreleased]

### Added

- next thing

## [1.2.0] - 2026-11-01

### Added

- feature A

### Security

- fix B

## [1.1.0] - 2026-10-01

- old

## [1.0.0] - 2026-09-01

[1.2.0]: https://example.com/compare/v1.1.0...v1.2.0
"""


def test_changelog_section_extraction():
    m = load_script()
    assert m.section(CHANGELOG, "1.2.0") == "### Added\n\n- feature A\n\n### Security\n\n- fix B"
    assert m.section(CHANGELOG, "v1.2.0") == m.section(CHANGELOG, "1.2.0")
    assert m.section(CHANGELOG, "1.1.0") == "- old"
    assert m.section(CHANGELOG, "Unreleased") == "### Added\n\n- next thing"
    assert m.section(CHANGELOG, "1.0.0") is None  # empty, link refs excluded
    assert m.section(CHANGELOG, "9.9.9") is None
    assert m.section(CHANGELOG, "1.2") is None  # no prefix matching


def test_changelog_script_cli(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text(CHANGELOG)
    script = str(ROOT / "scripts" / "changelog_section.py")
    ok = subprocess.run([sys.executable, script, "v1.1.0", str(f)], capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout == "- old\n"
    bad = subprocess.run([sys.executable, script, "v9.9.9", str(f)], capture_output=True, text=True)
    assert bad.returncode == 1 and bad.stdout == ""


def test_repo_changelog_has_unreleased_and_current_version():
    m = load_script()
    text = (ROOT / "CHANGELOG.md").read_text()
    assert m.section(text, "Unreleased")
    body = m.section(text, PYPROJECT_VERSION)
    assert body and "### Added" in body and "### Security" in body


# ---------------------------------------------------------------- redaction (#10 leftover)


@pytest.mark.parametrize("line", [
    "Authorization: Bearer abc.def-123",
    "authorization: Basic dXNlcjpwYXNz",
    "headers={'authorization': 'Bearer s3cr3t-tok', 'accept': '*/*'}",
    '{"Authorization": "Bearer s3cr3t-tok"}',
    "upstream said: invalid Bearer s3cr3t-tok",
    "AUTHORIZATION=s3cr3t-tok",
])
def test_redacts_authorization_and_bearer(line):
    out = redact(line)
    assert "s3cr3t" not in out and "abc.def" not in out and "dXNlcjpwYXNz" not in out
    assert "<redacted>" in out


def test_redaction_keeps_harmless_text():
    assert redact("the bearer of good news") == "the bearer of good news"
    assert redact("authorization required") == "authorization required"
    assert redact("headers={'accept': '*/*'}") == "headers={'accept': '*/*'}"

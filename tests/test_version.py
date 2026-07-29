"""Release metadata must not drift across package and public documentation."""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import version
from pathlib import Path

from hayate_auth import __version__

ROOT = Path(__file__).resolve().parents[1]


def _project() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as source:
        return tomllib.load(source)["project"]


def test_public_version_matches_project_and_installed_distribution() -> None:
    project_version = _project()["version"]
    assert __version__ == project_version == version("hayate-auth")


def test_readme_release_line_matches_project_version() -> None:
    project_version = _project()["version"]
    expected_line = ".".join(project_version.split(".")[:2])
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"Status: alpha \((\d+\.\d+)\.x\)", readme)
    assert match is not None
    assert match.group(1) == expected_line


def test_readme_direct_dependency_claim_matches_project_metadata() -> None:
    dependencies = _project()["dependencies"]
    expected_names = {
        re.split(r"[<>=!~ ;\[]", requirement, maxsplit=1)[0] for requirement in dependencies
    }
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"\*\*(\d+) direct runtime dependencies\*\*:\s+(.+?)\.",
        readme,
        re.DOTALL,
    )
    assert match is not None
    declared_names = set(re.findall(r"`([^`]+)`", match.group(2)))
    assert int(match.group(1)) == len(expected_names)
    assert declared_names == expected_names

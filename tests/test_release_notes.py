import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "release-notes.sh"
pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("sh") is None, reason="needs git and sh")


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=repo,
                   check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    for msg, tag in (("first", "v1.0.0"), ("pwndbg_imgui: a feature", "v1.1.0")):
        (tmp_path / "f").write_text(msg)
        git(tmp_path, "add", "f")
        git(tmp_path, "commit", "-q", "-m", msg)
        git(tmp_path, "tag", "-a", tag, "-m", tag)
    return tmp_path


def notes(repo: Path, tag: str, **env: str) -> str:
    return subprocess.run(["sh", str(SCRIPT), tag], cwd=repo, check=True, capture_output=True, text=True,
                          env={**os.environ, "GITHUB_REPOSITORY": "o/r", **env}).stdout


def test_hand_written_notes_come_first_with_pinned_images(repo: Path):
    (repo / "docs" / "releases").mkdir(parents=True)
    (repo / "docs" / "releases" / "v1.1.0.md").write_text(
        "**Summary.**\n\n![shot](v1.1.0/a.png)\n<img src=\"./v1.1.0/b.png\">\n")
    out = notes(repo, "v1.1.0")
    raw = "https://raw.githubusercontent.com/o/r/v1.1.0/docs/releases/v1.1.0/"
    assert out.startswith("**Summary.**")
    assert f"![shot]({raw}a.png)" in out and f'<img src="{raw}b.png">' in out
    assert "## All changes" in out and "- pwndbg_imgui: a feature (" in out and "- first" not in out
    assert "compare/v1.0.0...v1.1.0" in out
    # images added after the tag: point at a later commit instead
    assert "o/r/abc123/docs/releases/v1.1.0/a.png" in notes(repo, "v1.1.0", RELEASE_REF="abc123")


def test_without_hand_written_notes_only_the_commits(repo: Path):
    out = notes(repo, "v1.1.0")
    assert out.startswith("## Install") and "## Changes" in out and "- pwndbg_imgui: a feature (" in out

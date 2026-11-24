"""The shell scripts in deploy/ are run on the server as commands
(`admin-bff`, `deploy.sh`), so git must keep them executable."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted((ROOT / "deploy").glob("*.sh"))


def test_the_server_commands_exist() -> None:
    assert {p.name for p in SCRIPTS} >= {"admin-bff.sh", "deploy.sh"}


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_are_executable_in_git(script: Path) -> None:
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    entry = subprocess.run(  # noqa: S603 (fixed arguments, no shell)
        [git, "ls-files", "--stage", "--", script.relative_to(ROOT).as_posix()],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # Windows checkouts do not keep the bit: git update-index --chmod=+x <file>
    assert entry.startswith("100755 "), entry or "not tracked by git"

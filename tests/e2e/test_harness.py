"""The harness's own checks: a Python that cannot import what the agent
processes need is something the machine lacks, which the suite and the
demo report as a ``SetupError`` saying what to do, never as a failed step.

    python -m pytest tests/e2e/test_harness.py
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import harness


def test_a_module_the_agent_cannot_import_is_a_setup_error() -> None:
    with pytest.raises(harness.SetupError, match="pragmatic_no_such_module"):
        harness.check_python(os.environ, modules=("pragmatic_no_such_module",))


def test_the_agents_python_imports_the_sdks() -> None:
    harness.check_python(os.environ)


@pytest.mark.skipif(
    not getattr(stat, "UF_HIDDEN", 0) or not hasattr(os, "chflags"),
    reason="hidden file flags are a macOS and BSD feature",
)
def test_a_hidden_editable_install_is_named_with_its_fix(tmp_path: Path) -> None:
    """iCloud Drive marks the files of a virtual environment in Desktop or
    Documents hidden, and Python 3.13 and later skip a hidden ``.pth``
    file, so an editable install (``maturin develop``) stops importing."""
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    python = str(venv / "bin" / "python")
    site = subprocess.run(
        [python, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    source = tmp_path / "src"
    source.mkdir()
    (source / "editable_pkg.py").write_text("VALUE = 1\n")
    pth = Path(site) / "editable_pkg.pth"
    pth.write_text(f"{source}\n")

    harness.check_python(os.environ, modules=("editable_pkg",), python=python)
    assert harness.hidden_pth_files(python) == []

    os.chflags(pth, os.lstat(pth).st_flags | stat.UF_HIDDEN)
    hidden = harness.hidden_pth_files(python)
    assert [os.path.realpath(p) for p in hidden] == [os.path.realpath(pth)]
    if sys.version_info >= (3, 13):
        with pytest.raises(harness.SetupError) as caught:
            harness.check_python(os.environ, modules=("editable_pkg",), python=python)
        message = str(caught.value)
        assert "editable_pkg" in message and "hidden" in message
        assert "pip install ./crates/pragmatic-python" in message

# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test import."""

import re
import subprocess
import sys
from pathlib import Path

import spdx3_validate


def test_public_api_is_importable() -> None:
    """Test that the public API is importable."""
    for name in spdx3_validate.__all__:
        assert hasattr(spdx3_validate, name), name


def test_version_is_exposed() -> None:
    """Test that the version is exposed and looks like a version string."""
    assert isinstance(spdx3_validate.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", spdx3_validate.__version__)


def test_python_m_exit_status(tmp_path: Path) -> None:
    """``python -m spdx3_validate`` exits with the validation status."""
    # An unreadable --shacl file makes main() return 1 without network access
    missing = tmp_path / "missing.ttl"
    proc = subprocess.run(
        [sys.executable, "-m", "spdx3_validate", "-q", "--shacl", str(missing)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr

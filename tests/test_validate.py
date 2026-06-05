# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test spdx3validate function."""

import urllib.error
from pathlib import Path

import pytest

import spdx3_validate

DATA_DIR = Path(__file__).parent / "data"


def test_spdx3validate_is_callable() -> None:
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> a valid (truthy) result.
    result = spdx3_validate.spdx3validate([])
    assert isinstance(result, spdx3_validate.MergedResult)
    assert result.valid is True
    assert bool(result) is True
    assert result.results == []


def test_spdx3validate_invalid() -> None:
    """A known-invalid SPDX 3.0.1 document fails validation."""
    doc_path = DATA_DIR / "3.0.1" / "invalid" / "package_sbom_missing_creationinfo.json"
    try:
        result = spdx3_validate.spdx3validate([str(doc_path)])
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert result.valid is False
    assert bool(result) is False
    # The offending file is reported with concrete errors.
    bad = [r for r in result.results if not r.valid]
    assert bad
    assert any(r.schema_errors or r.shacl_errors for r in bad)


def test_spdx3validate_valid() -> None:
    """A known-valid SPDX 3.0.1 document validates successfully."""
    doc_path = DATA_DIR / "3.0.1" / "valid" / "package_sbom.json"
    try:
        result = spdx3_validate.spdx3validate([str(doc_path)])
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert result.valid is True
    assert all(r.valid for r in result.results)

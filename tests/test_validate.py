# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test the validate() library API and the spdx3validate() CLI entry point."""

import json
from pathlib import Path

import pytest

import spdx3_validate

DATA_DIR = Path(__file__).parent / "data"
VALID_DOC = DATA_DIR / "3.0.1" / "valid" / "package_sbom.json"
INVALID_DOC = DATA_DIR / "3.0.1" / "invalid" / "package_sbom_missing_creationinfo.json"


# --- Library API: validate() -------------------------------------------------


def test_validate_valid() -> None:
    """A known-valid document validates with no errors."""
    try:
        result = spdx3_validate.validate(str(VALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert result.valid
    assert bool(result) is True
    assert result.errors == []


def test_validate_invalid() -> None:
    """A known-invalid document reports attributed ValidationError objects."""
    try:
        result = spdx3_validate.validate(str(INVALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert not result.valid
    assert not result
    assert result.errors
    assert str(result)  # errors render as text
    for err in result.errors:
        assert isinstance(err, spdx3_validate.ValidationError)
        assert err.source == str(INVALID_DOC)
        assert err.kind in {"schema", "shacl"}
        assert err.message


def test_validate_no_sources_is_valid() -> None:
    """Validating nothing succeeds without touching the network."""
    result = spdx3_validate.validate([])
    assert result.valid
    assert result.errors == []


def test_validate_missing_context_raises(tmp_path: Path) -> None:
    """A document without an @context raises SpdxValidateError (no network)."""
    bad = tmp_path / "no_context.json"
    bad.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate(str(bad))


def test_validate_unknown_version_raises() -> None:
    """An unknown version string raises UnknownVersionError (no network)."""
    with pytest.raises(spdx3_validate.UnknownVersionError):
        spdx3_validate.validate([], version="9.9.9")


def test_error_and_result_rendering() -> None:
    """ValidationError / ValidationResult render as text (no network)."""
    err = spdx3_validate.ValidationError("a.json", "shacl", "boom")
    assert str(err) == "a.json [shacl]: boom"

    result = spdx3_validate.ValidationResult([err])
    assert not result
    assert not result.valid
    assert str(result) == "a.json [shacl]: boom"


def test_empty_result_is_valid_and_blank() -> None:
    """An empty ValidationResult is valid and renders as an empty string."""
    result = spdx3_validate.ValidationResult()
    assert result.valid
    assert bool(result) is True
    assert str(result) == ""


# --- CLI entry point: spdx3validate() (back-compat) --------------------------


def test_spdx3validate_is_callable() -> None:
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


def test_spdx3validate_valid() -> None:
    """A known-valid SPDX 3.0.1 document validates successfully."""
    try:
        rc = spdx3_validate.spdx3validate([str(VALID_DOC)])
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 0


def test_spdx3validate_invalid() -> None:
    """A known-invalid SPDX 3.0.1 document fails validation."""
    try:
        rc = spdx3_validate.spdx3validate([str(INVALID_DOC)])
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc != 0

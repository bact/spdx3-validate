# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test validation of SPDX 3 extensions with additional SHACL (``--shacl``)."""

from pathlib import Path
from typing import List

import pytest

import spdx3_validate

EXT_DIR = Path(__file__).parent / "data" / "3.0.1" / "extension"
EXT_SHACL = EXT_DIR / "synthetic-data.ttl"
EXT_NS = "https://example.org/spdx3-ext/synthetic-data/"

VALID_EXT_DOCS = [
    EXT_DIR / "valid-minimal.spdx3.json",
    EXT_DIR / "valid-full.spdx3.json",
    EXT_DIR / "valid-iri-node.spdx3.json",
]
# Valid against the SPDX model, but breaks the extension's own constraints
INVALID_EXT_DOC = EXT_DIR / "valid-ext-invalid.spdx3.json"


def _validate(doc: Path, extra_shacl: List[str]) -> spdx3_validate.ValidationResult:
    try:
        return spdx3_validate.validate(str(doc), extra_shacl=extra_shacl)
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")


@pytest.mark.parametrize("doc", VALID_EXT_DOCS, ids=lambda p: p.name)
def test_valid_extension_docs_pass_with_shacl(doc: Path) -> None:
    """Documents meeting the extension's constraints pass with its SHACL."""
    result = _validate(doc, [str(EXT_SHACL)])
    assert result.valid, str(result)


@pytest.mark.parametrize(
    "doc", VALID_EXT_DOCS + [INVALID_EXT_DOC], ids=lambda p: p.name
)
def test_extension_docs_pass_without_shacl(doc: Path) -> None:
    """Without the extension's SHACL its constraints are not checked (unchanged)."""
    result = _validate(doc, [])
    assert result.valid, str(result)


def test_extension_violations_reported_with_shacl() -> None:
    """Breaking the extension's own constraints is reported with its SHACL."""
    result = _validate(INVALID_EXT_DOC, [str(EXT_SHACL)])
    assert not result.valid
    assert all(e.kind == "shacl" for e in result.errors)
    assert all(e.source == str(INVALID_EXT_DOC) for e in result.errors)

    messages = "\n".join(e.message for e in result.errors)
    # generationMethod is missing (sh:minCount 1)
    assert "MinCountConstraintComponent" in messages
    assert EXT_NS + "generationMethod" in messages
    # syntheticFraction is 1.5 (sh:maxInclusive 1)
    assert "MaxInclusiveConstraintComponent" in messages
    # generatorModel points to a Person (sh:class AI/AIPackage), which needs
    # the merged ontology graph to resolve
    assert "ClassConstraintComponent" in messages
    assert len(result.errors) == 3


def test_extra_shacl_accepts_single_string() -> None:
    """``extra_shacl`` accepts a single location, like ``sources``."""
    try:
        result = spdx3_validate.validate(
            str(INVALID_EXT_DOC), extra_shacl=str(EXT_SHACL)
        )
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert len(result.errors) == 3


def test_missing_extra_shacl_raises() -> None:
    """An unreadable SHACL file raises SpdxValidateError."""
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate(
            str(VALID_EXT_DOCS[0]), extra_shacl=[str(EXT_DIR / "missing.ttl")]
        )


def test_cli_shacl_option() -> None:
    """The ``--shacl`` command line option is repeatable and applied."""
    from spdx3_validate.main import main

    try:
        assert main(["-q", "-j", str(INVALID_EXT_DOC)]) == 0
        assert main(["-q", "--shacl", str(EXT_SHACL), "-j", str(INVALID_EXT_DOC)]) == 1
        assert (
            main(
                [
                    "-q",
                    "--shacl",
                    str(EXT_SHACL),
                    "--shacl",
                    str(EXT_SHACL),
                    "-j",
                    str(VALID_EXT_DOCS[0]),
                ]
            )
            == 0
        )
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")


def test_cli_missing_shacl_fails() -> None:
    """The command line reports an unreadable SHACL file and fails."""
    from spdx3_validate.main import main

    assert (
        main(
            [
                "-q",
                "--shacl",
                str(EXT_DIR / "missing.ttl"),
                "-j",
                str(VALID_EXT_DOCS[0]),
            ]
        )
        == 1
    )

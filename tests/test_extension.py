# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test validation of SPDX 3 extensions with additional SHACL (``--shacl``)."""

import warnings
from pathlib import Path
from typing import List, Union

import pytest
import rdflib

import spdx3_validate
from spdx3_validate.core import ExtraShaclWarning, load_shacl, shacl_format

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


def _validate(
    doc: Path, extra_shacl: List[Union[str, Path]]
) -> spdx3_validate.ValidationResult:
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
    # generatorModel points to a Person (sh:class AI/AIPackage), checked
    # against the Person's rdf:type in the data graph
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


def test_cli_shacl_option(capsys: pytest.CaptureFixture[str]) -> None:
    """The ``--shacl`` command line option is repeatable and applied."""
    from spdx3_validate.main import main

    try:
        assert main(["-q", "-j", str(INVALID_EXT_DOC)]) == 0
        capsys.readouterr()
        assert main(["-q", "--shacl", str(EXT_SHACL), "-j", str(INVALID_EXT_DOC)]) == 1
        once = capsys.readouterr().out
        assert once.count("Violation of type") == 3
        # The same file given twice (even by another spelling) is loaded once,
        # so each violation is reported once
        assert (
            main(
                [
                    "-q",
                    "--shacl",
                    str(EXT_SHACL),
                    "--shacl",
                    str(EXT_DIR / ".." / "extension" / EXT_SHACL.name),
                    "-j",
                    str(INVALID_EXT_DOC),
                ]
            )
            == 1
        )
        assert capsys.readouterr().out.count("Violation of type") == 3
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


def test_duplicate_extra_shacl_loaded_once() -> None:
    """Giving the same SHACL file twice does not duplicate results."""
    result = _validate(INVALID_EXT_DOC, [str(EXT_SHACL), EXT_SHACL])
    assert len(result.errors) == 3


def test_extra_shacl_accepts_path() -> None:
    """``extra_shacl`` and :func:`load_shacl` accept :class:`pathlib.Path`."""
    assert len(load_shacl(EXT_SHACL)) > 0
    result = _validate(INVALID_EXT_DOC, [EXT_SHACL])
    assert len(result.errors) == 3


def test_cli_spdx3validate_accepts_single_string(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``spdx3validate(extra_shacl=...)`` accepts a single location."""
    try:
        rc = spdx3_validate.spdx3validate(
            [str(INVALID_EXT_DOC)], extra_shacl=str(EXT_SHACL)
        )
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 1
    assert capsys.readouterr().out.count("Violation of type") == 3


def test_cli_missing_shacl_fails_without_json() -> None:
    """``--shacl`` files are loaded even with no ``--json``, so errors show."""
    from spdx3_validate.main import main

    assert main(["-q", "--shacl", str(EXT_DIR / "missing.ttl")]) == 1


def test_validate_missing_shacl_raises_without_sources() -> None:
    """The library also loads extra SHACL when there is nothing to validate."""
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate([], extra_shacl=str(EXT_DIR / "missing.ttl"))


@pytest.mark.parametrize(
    "location, expected",
    [
        ("ext.ttl", "turtle"),
        ("ext.unknown", "turtle"),
        (Path("ext.jsonld"), "json-ld"),
        ("https://example.org/ext.ttl?raw=true", "turtle"),
        ("https://example.org/ext.ttl#frag", "turtle"),
        ("https://example.org/ext", None),
    ],
)
def test_shacl_format(location: Union[str, Path], expected: str) -> None:
    """The RDF format is guessed ignoring URL queries; unknown URLs use None
    so rdflib picks the format from the Content-Type."""
    assert shacl_format(location) == expected


# --- Malformed or SPDX-weakening extension files -----------------------------

TTL_PREFIXES = """\
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix core: <https://spdx.org/rdf/3.0.1/terms/Core/> .
@prefix ex: <https://example.org/ext/> .
"""


def _write_ttl(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "ext.ttl"
    path.write_text(TTL_PREFIXES + body, encoding="utf-8")
    return path


def test_malformed_extra_shacl_raises(tmp_path: Path) -> None:
    """A malformed shape raises SpdxValidateError naming the extra SHACL."""
    ttl = _write_ttl(
        tmp_path,
        "ex:Bad a sh:NodeShape ; sh:targetClass core:Person ;\n"
        "    sh:property [ sh:path core:name ; sh:maxCount 1, 2 ] .\n",
    )
    try:
        with pytest.raises(spdx3_validate.SpdxValidateError) as exc:
            spdx3_validate.validate(str(VALID_EXT_DOCS[0]), extra_shacl=str(ttl))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert str(ttl) in str(exc.value)


def test_cli_malformed_extra_shacl_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command line reports a malformed shape and fails."""
    from spdx3_validate.main import main

    ttl = _write_ttl(
        tmp_path,
        "ex:Bad a sh:NodeShape ; sh:targetClass core:Person ;\n"
        "    sh:property [ sh:path core:name ; sh:maxCount 1, 2 ] .\n",
    )
    try:
        assert main(["-q", "--shacl", str(ttl), "-j", str(VALID_EXT_DOCS[0])]) == 1
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert str(ttl) in capsys.readouterr().out


@pytest.mark.parametrize(
    "body",
    [
        "core:Element sh:deactivated true .\n",
        "ex:Shape a sh:NodeShape ; sh:deactivated true .\n",
        'core:Element rdfs:comment "changed" .\n',
        "<https://example.org/agent/bob> a owl:NamedIndividual, core:Person .\n",
    ],
    ids=["deactivate-spdx", "deactivate-own", "spdx-subject", "spdx-individual"],
)
def test_extra_shacl_weakening_spdx_warns(tmp_path: Path, body: str) -> None:
    """Content that can change SPDX validation itself triggers a warning."""
    ttl = _write_ttl(tmp_path, body)
    with pytest.warns(ExtraShaclWarning, match=str(ttl)):
        load_shacl(str(ttl))


def test_extension_shacl_does_not_warn() -> None:
    """A plain extension definition loads without warnings."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        graph = load_shacl(str(EXT_SHACL))
    assert isinstance(graph, rdflib.Graph)


def test_cli_extra_shacl_warning_printed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command line prints extra SHACL warnings to standard error."""
    from spdx3_validate.main import main

    ttl = _write_ttl(tmp_path, "core:Element sh:deactivated true .\n")
    try:
        main(["-q", "--shacl", str(ttl), "-j", str(VALID_EXT_DOCS[0])])
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "sh:deactivated" in err

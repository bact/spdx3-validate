# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test validation of SPDX 3 extensions with additional SHACL (``--shacl``)."""

import json
import warnings
from pathlib import Path
from typing import List, Tuple, Union

import pyshacl
import pyshacl.errors
import pytest
import rdflib
from rdflib import SH, URIRef
from rdflib.term import Node

import spdx3_validate
from spdx3_validate.core import (
    EXTENSION_CLASS_MESSAGE,
    ExtraShaclWarning,
    check_graph,
    extension_class_shape,
    load_shacl,
    load_validation_data,
    shacl_format,
)
from spdx3_validate.spdx_versions import SPDX_VERSIONS, SpdxVersion

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
    doc: Path,
    extra_shacl: List[Union[str, Path]],
    require_known_extensions: bool = False,
) -> spdx3_validate.ValidationResult:
    try:
        return spdx3_validate.validate(
            str(doc),
            extra_shacl=extra_shacl,
            require_known_extensions=require_known_extensions,
        )
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


def test_load_shacl_warning_points_at_caller(tmp_path: Path) -> None:
    """The warning is attributed to the caller's line, not to the library."""
    ttl = _write_ttl(tmp_path, "core:Element sh:deactivated true .\n")
    with pytest.warns(ExtraShaclWarning) as direct:
        load_shacl(ttl)
    assert {w.filename for w in direct} == {__file__}
    with pytest.warns(ExtraShaclWarning) as via_validate:
        spdx3_validate.validate([], extra_shacl=ttl)
    assert {w.filename for w in via_validate} == {__file__}


@pytest.mark.parametrize(
    "error",
    [
        pyshacl.errors.ValidationFailure("boom"),
        pyshacl.errors.ReportableRuntimeError("boom"),
    ],
    ids=["ValidationFailure", "ReportableRuntimeError"],
)
def test_non_shape_pyshacl_errors_not_blamed_on_extra_shacl(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """Only shape/constraint loading errors are reported as invalid shapes."""

    def fail(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(pyshacl, "validate", fail)
    with pytest.raises(type(error)) as exc:
        check_graph(rdflib.Graph(), rdflib.Graph(), SPDX_VERSIONS[-1], True)
    assert not isinstance(exc.value, spdx3_validate.SpdxValidateError)


@pytest.mark.parametrize(
    "error",
    [
        pyshacl.errors.ShapeLoadError("boom", "x"),
        pyshacl.errors.ConstraintLoadError("boom", "x"),
    ],
    ids=["ShapeLoadError", "ConstraintLoadError"],
)
def test_shape_load_errors_reported(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """Shape and constraint loading errors become ShaclShapesError."""

    def fail(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(pyshacl, "validate", fail)
    with pytest.raises(spdx3_validate.ShaclShapesError):
        check_graph(rdflib.Graph(), rdflib.Graph(), SPDX_VERSIONS[-1], True)


# --- Positive check that extension values are Extension subclasses ----------

TYPO_EXT_DOC = EXT_DIR / "typo-extension-type.spdx3.json"


def test_extension_type_typo_reported_when_required() -> None:
    """With require_known_extensions, an extension whose type IRI has a typo
    is reported."""
    result = _validate(TYPO_EXT_DOC, [str(EXT_SHACL)], True)
    assert not result.valid
    assert len(result.errors) == 1
    message = result.errors[0].message
    assert "ClassConstraintComponent" in message
    assert "https://spdx.org/rdf/3.0.1/terms/Extension/Extension" in message
    assert EXTENSION_CLASS_MESSAGE in message


@pytest.mark.parametrize("extra_shacl", [[], [EXT_SHACL]], ids=["none", "shacl"])
def test_extension_type_typo_not_reported_by_default(
    extra_shacl: List[Union[str, Path]],
) -> None:
    """Without require_known_extensions extension types stay open-world,
    with or without extra SHACL."""
    result = _validate(TYPO_EXT_DOC, extra_shacl)
    assert result.valid, str(result)


POLICY_TTL = """\
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix core: <https://spdx.org/rdf/3.0.1/terms/Core/> .
<urn:policy:NameShape> a sh:NodeShape ; sh:targetClass core:SpdxDocument ;
    sh:property [ sh:path core:name ; sh:minCount 1 ] .
"""


@pytest.mark.parametrize("doc", VALID_EXT_DOCS, ids=lambda p: p.name)
def test_policy_only_shacl_does_not_require_known_extensions(
    tmp_path: Path, doc: Path
) -> None:
    """A policy-only shapes file does not make extension types fail."""
    policy = tmp_path / "policy.ttl"
    policy.write_text(POLICY_TTL, encoding="utf-8")
    result = _validate(doc, [policy])
    assert result.valid, str(result)


def test_cli_require_known_extensions(capsys: pytest.CaptureFixture[str]) -> None:
    """``--require-known-extensions`` turns on the check on the command line."""
    from spdx3_validate.main import main

    args = ["-q", "--shacl", str(EXT_SHACL), "-j", str(TYPO_EXT_DOC)]
    try:
        assert main(args) == 0
        assert main(args + ["--require-known-extensions"]) == 1
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert EXTENSION_CLASS_MESSAGE in capsys.readouterr().out


def test_spdx3validate_require_known_extensions() -> None:
    """``spdx3validate()`` takes ``require_known_extensions`` too."""
    try:
        rc = spdx3_validate.spdx3validate(
            [str(TYPO_EXT_DOC)],
            extra_shacl=[str(EXT_SHACL)],
            require_known_extensions=True,
        )
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 1


def _shape_classes(shape: rdflib.Graph) -> List[Tuple[Node, Node]]:
    return [
        (path, cls)
        for prop in shape.subjects(SH["class"], None)
        for path in shape.objects(prop, SH.path)
        for cls in shape.objects(prop, SH["class"])
    ]


@pytest.mark.parametrize("version", SPDX_VERSIONS, ids=lambda v: v.pretty)
def test_extension_class_shape_uses_version_iris(version: SpdxVersion) -> None:
    """The shape is built from the term base IRI of the SPDX version."""
    shape = extension_class_shape(version, rdflib.Graph())
    assert _shape_classes(shape) == [
        (
            URIRef(version.rdf_base + "Core/extension"),
            URIRef(version.rdf_base + "Extension/Extension"),
        )
    ]
    assert (
        None,
        SH.targetSubjectsOf,
        URIRef(version.rdf_base + "Core/extension"),
    ) in shape


def _element_extension_class(version: SpdxVersion) -> rdflib.Graph:
    """A model fragment with the positive check on Core/Element, as in 3.0.0."""
    model = rdflib.Graph()
    prop = rdflib.BNode()
    element = URIRef(version.rdf_base + "Core/Element")
    model.add((element, SH.property, prop))
    model.add((prop, SH.path, URIRef(version.rdf_base + "Core/extension")))
    model.add((prop, SH["class"], URIRef(version.rdf_base + "Extension/Extension")))
    return model


@pytest.mark.parametrize("version", SPDX_VERSIONS, ids=lambda v: v.pretty)
def test_extension_class_shape_skipped_if_model_has_it(version: SpdxVersion) -> None:
    """No duplicate shape is added when the model already has the check."""
    model = _element_extension_class(version)
    assert len(extension_class_shape(version, model)) == 0


@pytest.mark.parametrize("version", SPDX_VERSIONS, ids=lambda v: v.pretty)
def test_extension_class_shape_needs_check_on_element(version: SpdxVersion) -> None:
    """Only a check attached to the Core/Element shape counts as the model's."""
    shape = extension_class_shape(version, rdflib.Graph())
    assert len(extension_class_shape(version, shape)) > 0


def test_extension_own_extension_shape_keeps_check(tmp_path: Path) -> None:
    """An extension file with its own ``extension``/``sh:class Extension``
    property shape does not disable the check for the rest of the document."""
    ttl = _write_ttl(
        tmp_path,
        "@prefix spdx-ext: <https://spdx.org/rdf/3.0.1/terms/Extension/> .\n"
        "ex:Foo a owl:Class, sh:NodeShape ; rdfs:subClassOf spdx-ext:Extension ;\n"
        "    sh:property [ sh:path core:extension ; sh:class spdx-ext:Extension ] .\n",
    )
    result = _validate(TYPO_EXT_DOC, [ttl, EXT_SHACL], True)
    assert len(result.errors) == 1
    assert EXTENSION_CLASS_MESSAGE in result.errors[0].message


DENY_LISTED_EXT_DOC = EXT_DIR / "deny-listed-extension-type.spdx3.json"


def test_deny_listed_extension_type_reported_once() -> None:
    """A value already rejected by the model's deny-list (here a Person) is
    not reported again by the positive check."""
    without = _validate(DENY_LISTED_EXT_DOC, [])
    with_shacl = _validate(DENY_LISTED_EXT_DOC, [EXT_SHACL], True)
    assert len(with_shacl.errors) == len(without.errors)
    messages = "\n".join(e.message for e in with_shacl.errors)
    assert "NotConstraintComponent" in messages
    assert EXTENSION_CLASS_MESSAGE not in messages


IMPORTED_EXT_DOC = EXT_DIR / "imported-iri-extension.spdx3.json"


def test_imported_iri_extension_reported() -> None:
    """An ExternalMap maps Elements, and an Extension is not an Element, so an
    IRI extension value listed in an ExternalMap is still reported."""
    result = _validate(IMPORTED_EXT_DOC, [EXT_SHACL], True)
    assert len(result.errors) == 1
    assert EXTENSION_CLASS_MESSAGE in result.errors[0].message


def test_imported_iri_extension_reported_by_3_0_0_model(tmp_path: Path) -> None:
    """The SPDX 3.0.0 model's own sh:class Extension check still reports an
    imported IRI extension value, without extra SHACL."""
    text = IMPORTED_EXT_DOC.read_text(encoding="utf-8").replace("3.0.1", "3.0.0")
    data = json.loads(text)
    for obj in data["@graph"]:
        if "import" in obj:
            obj["imports"] = obj.pop("import")
    doc = tmp_path / "imported-iri-extension-3.0.0.spdx3.json"
    doc.write_text(json.dumps(data), encoding="utf-8")
    result = _validate(doc, [])
    messages = "\n".join(e.message for e in result.errors)
    assert "ClassConstraintComponent" in messages
    assert "https://example.org/other/ext1" in messages


def test_extension_class_message_is_not_cli_specific() -> None:
    """The message is also shown to library users, so names no CLI option."""
    assert "--shacl" not in EXTENSION_CLASS_MESSAGE


@pytest.mark.parametrize(
    "pretty, expected", [("3.0.0", False), ("3.0.1", True)], ids=["3.0.0", "3.0.1"]
)
def test_extension_class_shape_against_published_model(
    pretty: str, expected: bool
) -> None:
    """SPDX 3.0.0 already requires sh:class Extension; 3.0.1 does not."""
    version = next(v for v in SPDX_VERSIONS if v.pretty == pretty)
    try:
        _, shacl_graph = load_validation_data(version)
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert bool(len(extension_class_shape(version, shacl_graph))) is expected

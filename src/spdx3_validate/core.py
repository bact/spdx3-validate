# SPDX-FileContributor: Joshua Watt
# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

"""Core SPDX 3 validation engine.

This module is the library heart of ``spdx3-validate``. It performs no console
output: loading problems are raised as :class:`SpdxValidateError`, and the
validation findings themselves are returned as data. The command-line interface
in :mod:`spdx3_validate.main` builds its progress spinners and error printing on
top of these primitives.
"""

from __future__ import annotations

import json
import textwrap
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import jsonschema
import pyshacl
import pyshacl.errors
import rdflib
from rdflib import OWL, RDF, RDFS, SH, BNode, Literal, URIRef
from rdflib.term import Node

from .spdx_versions import SPDX_VERSIONS, SpdxVersion, find_version


class SpdxValidateError(Exception):
    """Base class for errors raised while loading or validating documents."""


class UnknownVersionError(SpdxValidateError):
    """The requested SPDX version, or a document's ``@context``, is unknown."""


class ShaclShapesError(SpdxValidateError):
    """The SHACL shapes (e.g. from an extra SHACL file) are malformed."""


class ExtraShaclWarning(UserWarning):
    """An extra SHACL file contains content that can change SPDX validation.

    Extra SHACL files are trusted input: they are merged with the SPDX model,
    so they can deactivate or redefine its shapes, and individuals they
    declare are copied into the data graph before validation.
    """


#: A path or URL of an extra SHACL shapes / OWL ontology file.
ShaclLocation = Union[str, Path]


@dataclass
class ValidationError:
    """A single validation finding, attributed to the document it came from.

    Attributes:
        source: The document the error was found in (its :attr:`Document.source`).
            For a merged-graph check this is ``"(merged)"``.
        kind: ``"schema"`` for JSON Schema errors, ``"shacl"`` for SHACL ones.
        message: The human-readable description of the problem.
    """

    source: str
    kind: str
    message: str

    def __str__(self) -> str:
        return f"{self.source} [{self.kind}]: {self.message}"


def _resolve_version(
    version: Union[str, SpdxVersion, None],
) -> Optional[SpdxVersion]:
    """Normalise a version argument to a :class:`SpdxVersion` or ``None``.

    Accepts ``None`` (auto-detect from the documents), a :class:`SpdxVersion`,
    or a version string such as ``"3.0.1"``.
    """
    if version is None or isinstance(version, SpdxVersion):
        return version

    for v in SPDX_VERSIONS:
        if v.pretty == version:
            return v

    raise UnknownVersionError(f"Unknown SPDX version {version}")


def read_location(location: str) -> str:
    """Read the contents of a path or an URL."""
    if "://" in location:
        with urllib.request.urlopen(location) as f:
            content: bytes = f.read()
            return content.decode("utf-8")
    with Path(location).open("r", encoding="utf-8") as f:
        return f.read()


@dataclass
class Document:
    """An SPDX 3 document loaded from a source location.

    Attributes:
        source: Where the document came from. A path or URL for documents
            loaded with :meth:`load`, or any caller-supplied label for
            documents built with :meth:`from_text`.
        data: The parsed JSON content.
        graph: The document parsed as an RDF graph.
        version: The SPDX version detected from the document's ``@context``.
    """

    source: str
    data: Dict[str, Any]
    graph: rdflib.Graph
    version: SpdxVersion

    @classmethod
    def load(cls, source: str) -> Document:
        """Load and parse an SPDX 3 document from a path or URL.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
        """
        return cls.from_text(source, read_location(source))

    @classmethod
    def from_text(cls, source: str, text: str) -> Document:
        """Parse an SPDX 3 document already held in memory.

        Args:
            source: A label identifying the document (e.g. a filename), used
                only to attribute errors to it.
            text: The raw JSON-LD document content.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
        """
        data = json.loads(text)

        if "@context" not in data:
            raise SpdxValidateError(f"No @context found in {source}")

        version = find_version(data["@context"])
        if version is None:
            raise UnknownVersionError(
                f"{source} has unknown version @context {data['@context']}"
            )

        graph = rdflib.Graph()
        graph.parse(data=text, format="json-ld")

        return cls(source, data, graph, version)


def load_validation_data(version: SpdxVersion) -> Tuple[Dict[str, Any], rdflib.Graph]:
    """Download the JSON Schema and SHACL model for an SPDX *version*.

    Returns a ``(schema, shacl_graph)`` tuple.
    """
    with urllib.request.urlopen(version.schema_url) as f:
        schema = json.load(f)

    shacl_graph = rdflib.Graph()
    shacl_graph.parse(version.shacl_url)

    return schema, shacl_graph


def shacl_format(location: ShaclLocation) -> Optional[str]:
    """Guess the RDF format of an extra SHACL file from its *location*.

    The query and fragment of an URL are ignored. An URL whose format cannot
    be guessed gives ``None``, so rdflib uses the HTTP ``Content-Type``; a
    local file falls back to Turtle.
    """
    location = str(location)
    if "://" in location:
        path = urllib.parse.urlsplit(location).path
        return rdflib.util.guess_format(path)
    return rdflib.util.guess_format(location) or "turtle"


def _shacl_key(location: ShaclLocation) -> str:
    """Return a key identifying *location*, to load each file only once."""
    location = str(location)
    if "://" in location:
        return location
    return str(Path(location).resolve())


def unique_shacl_locations(locations: Iterable[ShaclLocation]) -> List[str]:
    """Return *locations* as strings, without repeats of the same file.

    Local paths are compared after resolving them, URLs as given. Loading a
    file twice would duplicate its blank-node shapes, and so its findings.
    """
    seen: Dict[str, str] = {}
    for location in locations:
        seen.setdefault(_shacl_key(location), str(location))
    return list(seen.values())


def _iri_examples(nodes: Iterable[Node], limit: int = 3) -> str:
    items = sorted({n.n3() for n in nodes})
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


def extra_shacl_warnings(graph: rdflib.Graph, location: str) -> List[str]:
    """Return warnings about content of an extra SHACL *graph* that can weaken
    or change validation against the SPDX model itself.

    Reported are triples whose subject is in an SPDX namespace (they redefine
    SPDX classes, properties, or shapes), ``owl:NamedIndividual`` instances of
    SPDX classes (pyshacl copies them into the data graph, so they can satisfy
    SPDX constraints, e.g. a dangling reference), and ``sh:deactivated true``
    (which silences the shape).
    """
    bases = tuple(sorted({v.rdf_base for v in SPDX_VERSIONS}))

    def in_spdx(n: Node) -> bool:
        return isinstance(n, URIRef) and str(n).startswith(bases)

    messages: List[str] = []

    spdx_subjects = [s for s in set(graph.subjects()) if in_spdx(s)]
    if spdx_subjects:
        messages.append(
            f"{location} has statements about terms in the SPDX namespace, "
            f"which change the SPDX model used for validation: "
            f"{_iri_examples(spdx_subjects)}"
        )

    individuals = [
        s
        for s in graph.subjects(RDF.type, OWL.NamedIndividual)
        if any(in_spdx(t) for t in graph.objects(s, RDF.type))
    ]
    if individuals:
        messages.append(
            f"{location} declares owl:NamedIndividual instances of SPDX "
            f"classes, which are copied into every validated document: "
            f"{_iri_examples(individuals)}"
        )

    deactivated = [
        s
        for s, o in graph.subject_objects(SH.deactivated)
        if isinstance(o, Literal) and o.toPython() is True
    ]
    if deactivated:
        messages.append(
            f"{location} deactivates shapes with sh:deactivated true: "
            f"{_iri_examples(deactivated)}"
        )

    return messages


def load_shacl(location: ShaclLocation) -> rdflib.Graph:
    """Load an additional SHACL shapes / OWL ontology file from a path or URL.

    This is how the definitions of an SPDX 3 extension (its classes, their
    ``rdfs:subClassOf`` links to ``Extension/Extension``, and its SHACL
    shapes) are supplied. The RDF format is guessed with :func:`shacl_format`.

    The file is trusted input: it is merged with the SPDX model, so it can
    weaken SPDX validation. An :class:`ExtraShaclWarning` is emitted for each
    finding of :func:`extra_shacl_warnings`.

    Raises:
        SpdxValidateError: The file cannot be read or parsed.
    """
    return _load_shacl(location, stacklevel=3)


def _load_shacl(location: ShaclLocation, stacklevel: int) -> rdflib.Graph:
    """Implement :func:`load_shacl`, warning at *stacklevel* (counted from
    this function) so that warnings point at the user's call."""
    location = str(location)
    graph = rdflib.Graph()
    try:
        graph.parse(location, format=shacl_format(location))
    except Exception as e:
        raise SpdxValidateError(f"Unable to load SHACL from {location}: {e}") from e

    for message in extra_shacl_warnings(graph, location):
        warnings.warn(message, ExtraShaclWarning, stacklevel=stacklevel)
    return graph


def shacl_shapes_error(e: ShaclShapesError, extra_shacl: Iterable[str]) -> str:
    """Describe a malformed-shapes error, naming the extra SHACL files."""
    extra = list(extra_shacl)
    if extra:
        return f"Invalid SHACL shapes in the extra SHACL ({', '.join(extra)}): {e}"
    return f"Invalid SHACL shapes: {e}"


def merge_shacl(
    shacl_graph: rdflib.Graph, extra: Iterable[rdflib.Graph]
) -> rdflib.Graph:
    """Return a new graph holding *shacl_graph* plus every graph in *extra*.

    :func:`check_graph` passes the same graph to pyshacl as both the shapes
    graph and the ontology graph, so merging extra definitions here makes
    their shapes run *and* their ``rdfs:subClassOf`` triples visible to
    ``sh:class`` checks. *shacl_graph* itself is left unmodified.
    """
    merged = rdflib.Graph()
    merged += shacl_graph
    for g in extra:
        merged += g
    return merged


EXTENSION_CLASS_MESSAGE = (
    "Value of extension is not of a class derived from Extension. "
    "Its type is unknown or not an Extension; is it defined in the supplied "
    "extension definitions, using the term IRIs of this SPDX version?"
)


def extension_class_shape(
    version: SpdxVersion, model_graph: rdflib.Graph
) -> rdflib.Graph:
    """Return a SHACL shape requiring every ``Core/extension`` value to be an
    ``Extension/Extension``.

    SPDX 3.0.1 only checks ``Core/extension`` values against a deny-list of
    classes known not to derive from ``Extension``, because subclasses defined
    by custom extensions cannot be known in advance. When the caller asks to
    require known extensions (``require_known_extensions`` of
    :func:`validate`), this shape adds the positive check: each value must have an ``rdf:type`` that is, via
    ``rdfs:subClassOf`` in the merged ontology, a subclass of
    ``Extension/Extension``. A value whose type is unknown (e.g. a typo in the
    type IRI) or not an Extension is reported.

    The IRIs are built from the term base of *version* (``.../3.0.0/terms/``
    or ``.../3.0.1/terms/``). *model_graph* must be the SPDX model alone,
    before any extension definitions are merged in. An empty graph is returned
    if its ``Core/Element`` shape already has this positive check, as the SPDX
    3.0.0 model does, so that each violation is not reported twice.
    """
    element = URIRef(version.rdf_base + "Core/Element")
    extension_prop = URIRef(version.rdf_base + "Core/extension")
    extension_cls = URIRef(version.rdf_base + "Extension/Extension")

    shape = rdflib.Graph()
    for prop_shape in model_graph.objects(element, SH.property):
        if (prop_shape, SH.path, extension_prop) in model_graph and (
            prop_shape,
            SH["class"],
            extension_cls,
        ) in model_graph:
            return shape

    node_shape = BNode()
    prop_shape = BNode()
    shape.add((node_shape, RDF.type, SH.NodeShape))
    shape.add((node_shape, SH.targetSubjectsOf, extension_prop))
    shape.add((node_shape, SH.property, prop_shape))
    shape.add((prop_shape, SH.path, extension_prop))
    shape.add((prop_shape, SH["class"], extension_cls))
    shape.add((prop_shape, SH.message, Literal(EXTENSION_CLASS_MESSAGE, lang="en")))
    return shape


def schema_validator(schema: Dict[str, Any]) -> jsonschema.protocols.Validator:
    """Return a ``jsonschema`` validator, checking that *schema* is well formed.

    Raises:
        jsonschema.exceptions.SchemaError: The schema itself is invalid.
    """
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    # validator_for()'s return type varies with the jsonschema/types-jsonschema
    # version resolved, so assign through an annotation instead of cast() --
    # cast() is flagged "redundant" in environments where this is already typed.
    validator: jsonschema.protocols.Validator = validator_cls(schema)
    return validator


def _schema_error(
    source: str, err: jsonschema.exceptions.ValidationError
) -> ValidationError:
    """Build a :class:`ValidationError` from a ``jsonschema`` error."""
    if isinstance(err.instance, str):
        message = err.message
    else:
        message = "Is not valid"
    return ValidationError(source, "schema", f"{err.json_path}: {message}")


def derives_from(cls: Node, target: Node, shacl_graph: rdflib.Graph) -> bool:
    """Return True if RDF class *cls* is, or derives from, *target*."""
    if cls == target:
        return True

    for subclass in shacl_graph.objects(cls, RDFS.subClassOf):
        if derives_from(subclass, target, shacl_graph):
            return True

    return False


def check_graph(
    graph: rdflib.Graph,
    shacl_graph: rdflib.Graph,
    current_version: SpdxVersion,
    error_external: bool,
) -> List[str]:
    """Validate *graph* against *shacl_graph*, returning a list of error strings.

    External ``spdxId`` references declared in an ``ExternalMap`` are not
    reported as missing. When *error_external* is true, an ``spdxId`` that is
    both imported and defined in the document is reported as an error.

    Raises:
        ShaclShapesError: A shape in *shacl_graph* is malformed.
    """
    errors: List[str] = []

    # pyshacl.validate() has no return type annotation, so its result is
    # typed here via annotation to restore type checking for the rest of
    # this function.
    try:
        validate_result: Tuple[bool, rdflib.Graph, str] = pyshacl.validate(
            graph,
            shacl_graph=shacl_graph,
            ont_graph=shacl_graph,
        )
    except (
        pyshacl.errors.ShapeLoadError,
        pyshacl.errors.ConstraintLoadError,
        pyshacl.errors.RuleLoadError,
    ) as shacl_err:
        # A malformed shape, e.g. one with two sh:maxCount, from an extra
        # SHACL file. Other pyshacl errors are not about the shapes, so they
        # propagate unchanged.
        raise ShaclShapesError(str(shacl_err)) from shacl_err
    conforms, results, _ = validate_result

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri: Optional[Node]) -> str:
            assert uri is not None
            return nm.normalizeUri(str(uri))

        def pnode(n: Optional[Node]) -> str:
            if n:
                return n.n3()
            return "-"

        extension_prop = URIRef(current_version.rdf_base + "Core/extension")
        extension_cls = URIRef(current_version.rdf_base + "Extension/Extension")

        # Collect all external map references
        external_spdxids: set[str] = set()
        for spdxid in current_version.get_imports(graph):
            # If the SpdxID is in the graph as a subject, than do
            # not mark it as an external SpdxID, since there is a
            # resolved definition for it
            if (spdxid, None, None) in graph:
                if error_external:
                    errors.append(
                        f"ERROR: {str(spdxid)} in an ExternalMap and also defined in the document"
                    )
            else:
                external_spdxids.add(str(spdxid))

        def check_external_ref_error(r: Node) -> bool:
            if (r, RDF.type, SH.ValidationResult) not in results:
                return False

            if (r, SH.resultSeverity, SH.Violation) not in results:
                return False

            if (
                r,
                SH.sourceConstraintComponent,
                SH.ClassConstraintComponent,
            ) not in results:
                return False

            is_element = False
            for ss in results.objects(r, SH.sourceShape):
                if is_element:
                    break

                for cls in results.objects(ss, SH["class"]):
                    is_element = derives_from(
                        cls,
                        URIRef(current_version.rdf_base + "Core/Element"),
                        shacl_graph,
                    )
                    if is_element:
                        break

            if not is_element:
                return False

            for v in results.objects(r, SH.value):
                if str(v) in external_spdxids:
                    return True

            return False

        def check_extension_class_duplicate(r: Node) -> bool:
            """True for a positive extension class check result whose value the
            model's deny-list of non-Extension classes already rejected."""
            if (
                r,
                SH.sourceConstraintComponent,
                SH.ClassConstraintComponent,
            ) not in results or (r, SH.resultPath, extension_prop) not in results:
                return False
            if not any(
                (ss, SH["class"], extension_cls) in results
                for ss in results.objects(r, SH.sourceShape)
            ):
                return False

            focus = results.value(r, SH.focusNode)
            value = results.value(r, SH.value)
            for other in results.subjects(SH.value, value):
                if (
                    (other, SH.focusNode, focus) in results
                    and (other, SH.resultPath, extension_prop) in results
                    and (
                        other,
                        SH.sourceConstraintComponent,
                        SH.NotConstraintComponent,
                    )
                    in results
                ):
                    return True
            return False

        for report in results.subjects(RDF.type, SH.ValidationReport):
            for r in results.objects(report, SH.result):
                if check_external_ref_error(r) or check_extension_class_duplicate(r):
                    continue

                e: List[str] = []
                e.append(
                    f"Violation of type {norm(results.value(r, SH.sourceConstraintComponent))}:"
                )
                e.append(f"\tSeverity: {norm(results.value(r, SH.resultSeverity))}")
                pg = rdflib.Graph()
                pg += results.triples((results.value(r, SH.sourceShape), None, None))
                if pg:
                    e.append("\tSource Shape:")
                    e.append(
                        textwrap.indent(pg.serialize(format="ttl").strip(), "\t\t")
                    )
                e.append(f"\tFocus Node: {pnode(results.value(r, SH.focusNode))}")
                e.append(f"\tValue Node: {pnode(results.value(r, SH.value))}")
                e.append(f"\tResult path: {pnode(results.value(r, SH.resultPath))}")
                e.append(f"\tMessage: {results.value(r, SH.resultMessage) or '-'}")
                e.append("")

                errors.append("\n".join(e))

    return errors


@dataclass
class ValidationResult:
    """The outcome of validating one or more SPDX 3 documents.

    ``errors`` is a list of :class:`ValidationError`. A result is truthy when
    validation passed, so it reads naturally::

        result = validate("sbom.json")
        if not result:
            print(result)  # prints the errors, one per line
    """

    errors: List[ValidationError] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """True when no validation errors were found."""
        return not self.errors

    def __bool__(self) -> bool:
        return self.valid

    def __str__(self) -> str:
        return "\n".join(str(e) for e in self.errors)


def validate(
    sources: Union[str, Iterable[str]],
    *,
    version: Union[str, SpdxVersion, None] = None,
    check_merged: bool = False,
    extra_shacl: Union[ShaclLocation, Iterable[ShaclLocation]] = (),
    require_known_extensions: bool = False,
) -> ValidationResult:
    """Validate one or more SPDX 3 documents against schema and SHACL rules.

    Args:
        sources: A single path or URL, or an iterable of them.
        version: SPDX version to validate against (e.g. ``"3.0.1"``). When
            ``None`` (the default) the version is detected from each document's
            ``@context``.
        check_merged: Also validate the graph formed by merging every document,
            which catches type errors across ``ExternalMap`` references. Skipped
            if any document already failed.
        extra_shacl: A path or URL, or an iterable of them, of additional
            SHACL shapes / OWL ontology files (e.g. the definition of an SPDX 3
            extension). Each distinct file is merged into both the SHACL shapes
            graph and the ontology graph used for validation, so the
            extension's own constraints are checked. These files are trusted:
            they can weaken SPDX validation, which emits an
            :class:`ExtraShaclWarning`. They are loaded even if *sources* is
            empty.
        require_known_extensions: Also require every ``Core/extension``
            value to be of a class derived from ``Extension/Extension`` in the
            SPDX model or in *extra_shacl* (see :func:`extension_class_shape`),
            so an extension of an unknown type, e.g. a typo, is reported.

    Returns:
        ValidationResult: The collected :class:`ValidationError` findings
            (empty when everything is valid).

    Raises:
        SpdxValidateError: A document or an *extra_shacl* file cannot be
            loaded, a shape is malformed, or documents declare incompatible
            versions.
        UnknownVersionError: *version* or a document ``@context`` is unknown.
    """
    if isinstance(sources, str):
        sources = [sources]
    if isinstance(extra_shacl, (str, Path)):
        extra_shacl = [extra_shacl]
    extra_locations = unique_shacl_locations(extra_shacl)
    extra_graphs: List[rdflib.Graph] = []
    for location in extra_locations:
        # A plain loop (not a comprehension, which is its own frame before
        # Python 3.12) so that the warning points at validate()'s caller.
        extra_graphs.append(_load_shacl(location, stacklevel=3))

    resolved_version = _resolve_version(version)

    documents: List[Document] = []
    for source in sources:
        doc = Document.load(source)
        if resolved_version is None:
            resolved_version = doc.version
        elif doc.version != resolved_version:
            raise SpdxValidateError(
                f"{source} has incompatible version {doc.version.pretty}. "
                f"Other documents are {resolved_version.pretty}"
            )
        documents.append(doc)

    if not documents:
        return ValidationResult()

    # documents is non-empty, so the loop above set resolved_version at least once.
    assert resolved_version is not None

    schema, shacl_graph = load_validation_data(resolved_version)
    if require_known_extensions:
        extra_graphs.append(extension_class_shape(resolved_version, shacl_graph))
    if extra_graphs:
        shacl_graph = merge_shacl(shacl_graph, extra_graphs)

    try:
        validator = schema_validator(schema)
    except jsonschema.exceptions.SchemaError as e:
        raise SpdxValidateError(
            f"Invalid schema {resolved_version.schema_url}: {e}"
        ) from e

    try:
        errors: List[ValidationError] = []
        for doc in documents:
            errors.extend(
                _schema_error(doc.source, e) for e in validator.iter_errors(doc.data)
            )
            errors.extend(
                ValidationError(doc.source, "shacl", msg)
                for msg in check_graph(doc.graph, shacl_graph, resolved_version, True)
            )

        if len(documents) > 1 and check_merged and not errors:
            merged = rdflib.Graph()
            for doc in documents:
                merged += doc.graph
            errors.extend(
                ValidationError("(merged)", "shacl", msg)
                for msg in check_graph(merged, shacl_graph, resolved_version, False)
            )
    except ShaclShapesError as e:
        raise ShaclShapesError(shacl_shapes_error(e, extra_locations)) from e

    return ValidationResult(errors)

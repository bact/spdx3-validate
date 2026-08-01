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

import copy
import json
import textwrap
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import jsonschema
import pyshacl
import rdflib
from rdflib import RDF, RDFS, SH, URIRef
from rdflib.term import Node

from .spdx_versions import SPDX_VERSIONS, SpdxVersion, find_version


class SpdxValidateError(Exception):
    """Base class for errors raised while loading or validating documents."""


class UnknownVersionError(SpdxValidateError):
    """The requested SPDX version, or a document's ``@context``, is unknown."""


class ResourceNotFoundError(SpdxValidateError, FileNotFoundError):
    """A required schema, shape, or context file was not found."""


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
        try:
            with urllib.request.urlopen(location) as f:
                content: bytes = f.read()
                return content.decode("utf-8")
        except OSError as e:
            raise ResourceNotFoundError(f"Failed to read URL {location}: {e}") from e
    try:
        with Path(location).open("r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError as e:
        raise ResourceNotFoundError(f"File not found: {location}") from e


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
    def load(
        cls,
        source: str,
        *,
        context_urls: Optional[List[str]] = None,
        model_dir: Optional[str] = None,
    ) -> Document:
        """Load and parse an SPDX 3 document from a path or URL.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
            ResourceNotFoundError: The input document file or local context
                file does not exist.
        """
        return cls.from_text(
            source,
            read_location(source),
            context_urls=context_urls,
            model_dir=model_dir,
        )

    @classmethod
    def from_text(
        cls,
        source: str,
        text: str,
        *,
        context_urls: Optional[List[str]] = None,
        model_dir: Optional[str] = None,
    ) -> Document:
        """Parse an SPDX 3 document already held in memory.

        Args:
            source: A label identifying the document (e.g. a filename), used
                only to attribute errors to it.
            text: The raw JSON-LD document content.
            context_urls: Optional list of local file paths or URLs for
                @context.
            model_dir: Optional model directory containing
                v[VERSION]/spdx-context.jsonld.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
            ResourceNotFoundError: A specified context file does not exist.
        """
        data = json.loads(text)

        if "@context" not in data:
            raise SpdxValidateError(f"No @context found in {source}")

        version = find_version(data["@context"])
        if version is None:
            raise UnknownVersionError(
                f"{source} has unknown version @context {data['@context']}"
            )

        actual_context_url: Optional[str] = None
        if context_urls:
            actual_context_url = context_urls[0]
            if ("://" not in actual_context_url) and (
                not Path(actual_context_url).is_file()
            ):
                raise ResourceNotFoundError(
                    f"Specified context file does not exist: {actual_context_url}"
                )
        elif model_dir:
            target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-context.jsonld"
            if not target_path.is_file():
                raise ResourceNotFoundError(
                    f"JSON-LD context file {target_path.name} not found "
                    f"in SPDX3VALIDATE_MODEL_DIR at {target_path}"
                )
            actual_context_url = str(target_path)

        graph = rdflib.Graph()
        if actual_context_url:
            if "://" in actual_context_url:
                with urllib.request.urlopen(actual_context_url) as f:
                    ctx_obj = json.load(f)
            else:
                with open(actual_context_url, "r", encoding="utf-8") as f:
                    ctx_obj = json.load(f)

            ctx_data = copy.deepcopy(data)
            if "@context" in ctx_obj:
                ctx_data["@context"] = ctx_obj["@context"]
            else:
                ctx_data["@context"] = ctx_obj
            graph.parse(data=json.dumps(ctx_data), format="json-ld")
        else:
            graph.parse(data=text, format="json-ld")

        return cls(source, data, graph, version)


def load_validation_data(
    version: SpdxVersion,
    *,
    schema_urls: Optional[List[str]] = None,
    shacl_urls: Optional[List[str]] = None,
    model_dir: Optional[str] = None,
) -> Tuple[Dict[str, Any], rdflib.Graph]:
    """Load the JSON Schema and SHACL model for an SPDX *version*.

    Resolution precedence for each resource:
    explicit parameter (`schema_urls` / `shacl_urls`) > `model_dir`
    > network default.

    Args:
        version: The SPDX version to load models for.
        schema_urls: Optional list of local file paths or URLs for JSON Schema.
            Takes precedence over `model_dir`.
        shacl_urls: Optional list of local file paths or URLs for SHACL shapes.
            Takes precedence over `model_dir`.
        model_dir: Optional directory containing versioned models (v[VERSION]/).
            Used if explicit resource lists are omitted.

    Returns a ``(schema, shacl_graph)`` tuple.

    Raises:
        ResourceNotFoundError: A specified or expected schema or SHACL file
            does not exist.
    """
    if schema_urls:
        actual_schema_url = schema_urls[0]
        if "://" not in actual_schema_url and not Path(actual_schema_url).is_file():
            raise ResourceNotFoundError(
                f"Specified schema file does not exist: {actual_schema_url}"
            )
    elif model_dir:
        target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-json-schema.json"
        if not target_path.is_file():
            raise ResourceNotFoundError(
                f"Schema file {target_path.name} not found in "
                f"SPDX3VALIDATE_MODEL_DIR at {target_path}"
            )
        actual_schema_url = str(target_path)
    else:
        actual_schema_url = version.schema_url

    if shacl_urls:
        actual_shacl_url = shacl_urls[0]
        if "://" not in actual_shacl_url and not Path(actual_shacl_url).is_file():
            raise ResourceNotFoundError(
                f"Specified shapes file does not exist: {actual_shacl_url}"
            )
    elif model_dir:
        target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-model.ttl"
        if not target_path.is_file():
            raise ResourceNotFoundError(
                f"SHACL shapes file {target_path.name} not found in "
                f"SPDX3VALIDATE_MODEL_DIR at {target_path}"
            )
        actual_shacl_url = str(target_path)
    else:
        actual_shacl_url = version.shacl_url

    if "://" in actual_schema_url:
        with urllib.request.urlopen(actual_schema_url) as f:
            schema = json.load(f)
    else:
        with open(actual_schema_url, "r", encoding="utf-8") as f:
            schema = json.load(f)

    shacl_graph = rdflib.Graph()
    shacl_graph.parse(actual_shacl_url)

    return schema, shacl_graph


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
    """
    errors: List[str] = []

    # pyshacl.validate() has no return type annotation, so its result is
    # typed here via annotation to restore type checking for the rest of
    # this function.
    validate_result: Tuple[bool, rdflib.Graph, str] = pyshacl.validate(
        graph,
        shacl_graph=shacl_graph,
        ont_graph=shacl_graph,
    )
    conforms, results, _ = validate_result

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri: Optional[Node]) -> str:
            if uri is None:
                return "-"
            return nm.normalizeUri(str(uri))

        def pnode(n: Optional[Node]) -> str:
            if n:
                return n.n3()
            return "-"

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

        for report in results.subjects(RDF.type, SH.ValidationReport):
            for r in results.objects(report, SH.result):
                if check_external_ref_error(r):
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
    schema_urls: Optional[List[str]] = None,
    shacl_urls: Optional[List[str]] = None,
    context_urls: Optional[List[str]] = None,
    model_dir: Optional[str] = None,
) -> ValidationResult:
    """Validate one or more SPDX 3 documents against schema and SHACL rules.

    Resolution precedence for each resource (`schema`, `shapes`, `context`):
    explicit list (`schema_urls`, `shacl_urls`, `context_urls`)
    > `model_dir` > network default.

    Args:
        sources: A single path or URL, or an iterable of them.
        version: SPDX version to validate against (e.g. ``"3.0.1"``). When
            ``None`` (the default) the version is detected from each document's
            ``@context``.
        check_merged: Also validate the graph formed by merging every document,
            which catches type errors across ``ExternalMap`` references. Skipped
            if any document already failed.
        schema_urls: Optional list of local file paths or URLs for JSON Schema.
            Takes precedence over `model_dir`.
        shacl_urls: Optional list of local file paths or URLs for SHACL shapes.
            Takes precedence over `model_dir`.
        context_urls: Optional list of local file paths or URLs for JSON-LD
            @context. Takes precedence over `model_dir`.
        model_dir: Optional directory containing versioned models (v[VERSION]/).
            Used for any resources not explicitly overridden above.

    Returns:
        ValidationResult: The collected :class:`ValidationError` findings
            (empty when everything is valid).

    Raises:
        SpdxValidateError: A document cannot be loaded, or documents declare
            incompatible versions.
        UnknownVersionError: *version* or a document ``@context`` is unknown.
        ResourceNotFoundError: A specified or expected model/context file does
            not exist.
    """
    if isinstance(sources, str):
        sources = [sources]

    resolved_version = _resolve_version(version)

    documents: List[Document] = []
    for source in sources:
        doc = Document.load(
            source,
            context_urls=context_urls,
            model_dir=model_dir,
        )
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

    if resolved_version is None:
        raise SpdxValidateError("Unable to determine SPDX version")

    schema, shacl_graph = load_validation_data(
        resolved_version,
        schema_urls=schema_urls,
        shacl_urls=shacl_urls,
        model_dir=model_dir,
    )

    try:
        validator = schema_validator(schema)
    except jsonschema.exceptions.SchemaError as e:
        raise SpdxValidateError(
            f"Invalid schema {resolved_version.schema_url}: {e}"
        ) from e

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

    return ValidationResult(errors)

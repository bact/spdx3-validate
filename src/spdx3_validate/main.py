# Copyright (c) 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

import argparse
import contextlib
import json
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

import halo
import jsonschema
import pyshacl
import rdflib
from jsonschema.exceptions import ValidationError
from rdflib import RDF, RDFS, SH, Graph, URIRef
from rdflib.term import Node

from .version import VERSION
from .spdx_versions import find_version, SpdxVersion, SPDX_VERSIONS
from .errors import Spdx3ValidateError, UnsupportedVersionError, SchemaError
from .result import (
    FileResult,
    ProgressFactory,
    ValidationResult,
    null_progress,
)


def read_location(location: str) -> Union[str, bytes]:
    if "://" in location:
        with urllib.request.urlopen(location) as f:
            data: bytes = f.read()
            return data
    elif location == "-":
        return sys.stdin.read()
    else:
        with Path(location).open("r", encoding="utf-8") as f:
            return f.read()


def derives_from(cls: Node, target: Node, shacl_graph: Graph) -> bool:
    if cls == target:
        return True

    for subclass in shacl_graph.objects(cls, RDFS.subClassOf):
        if derives_from(subclass, target, shacl_graph):
            return True

    return False


def check_graph(
    graph: Graph,
    shacl_graph: Graph,
    current_version: SpdxVersion,
    error_external: bool,
) -> List[str]:
    errors: List[str] = []

    conforms, results, _ = pyshacl.validate(
        graph,
        shacl_graph=shacl_graph,
        ont_graph=shacl_graph,
    )

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri: Any) -> str:
            return nm.normalizeUri(uri)

        def pnode(n: Optional[Node]) -> str:
            if n:
                return n.n3()
            return "-"

        # Collect all external map references
        external_spdxids: Set[str] = set()
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

                e = []
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


def iter_validation_errors(err: ValidationError) -> Iterator[ValidationError]:
    if err.context:
        for e in err.context:
            yield e
            yield from iter_validation_errors(e)


def print_schema_error(err: ValidationError, filename: str, indent: int = 0) -> None:
    def print_err(
        e: ValidationError,
        indent: int,
        fn: Optional[str] = None,
        message: bool = False,
    ) -> None:
        loc = e.json_path
        if fn:
            loc = f"{fn}::{loc}"

        if isinstance(e.instance, str):
            m = e.message
        else:
            m = "Is not valid"

        print((" " * indent) + f"{loc}: {m}")

    print_err(err, indent, filename)

    if err.context:
        i_str = " " * (indent + 2)
        print(i_str + "This error was caused by other underlying errors:")

        error_map: Dict[Tuple[Tuple[Any, ...], str], ValidationError] = {}
        for e in iter_validation_errors(err):
            error_map[(tuple(e.absolute_path), "")] = e

        error_list = [
            error_map[k]
            for k in sorted(
                error_map.keys(),
                key=lambda k: (len(k[0]), k[0], k[1]),
                reverse=True,
            )
        ]
        for e in error_list:
            print_err(e, indent + 4, message=True)

    print()


def main(cmdline_args: Optional[List[str]] = None) -> int:
    """Main function for CLI. Returns exit code."""
    parser = argparse.ArgumentParser(
        description=f"Validate SPDX 3 files Version {VERSION}"
    )

    parser.add_argument(
        "--json",
        "-j",
        default=[],
        action="append",
        help="Validate SPDX 3 JSON file (URL, path, or '-')",
    )
    parser.add_argument(
        "--spdx-version",
        "-s",
        default="auto",
        choices=[v.pretty for v in SPDX_VERSIONS] + ["auto"],
        help="SPDX Version to use, or 'auto' to determine version from input files",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "--no-merge",
        action="store_false",
        dest="check_merged",
        help="Do not validate merged documents",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Run quietly (do not show progress)",
    )
    args = parser.parse_args(cmdline_args)

    current_version = None if args.spdx_version == "auto" else args.spdx_version

    try:
        result = spdx3validate(
            args.json,
            current_version,
            args.check_merged,
            progress=_halo_progress(args.quiet),
        )
    except (Spdx3ValidateError, urllib.error.URLError) as e:
        print(e)
        return 1

    return _report(result)


def _halo_progress(quiet: bool) -> ProgressFactory:
    """Build a progress factory for CLI use."""

    @contextlib.contextmanager
    def factory(text: str) -> Iterator[Any]:
        with halo.Halo(text, enabled=not quiet) as spinner:
            yield spinner

    return factory


def _report(result: ValidationResult) -> int:
    """Print a ValidationResult for the CLI and return an exit code."""
    for f in result.files:
        for msg in f.load_errors:
            print(msg)

        if f.schema_errors:
            print(f"ERROR: JSON Schema validation failed for {f.location}:")
            for e in f.schema_errors:
                print_schema_error(e, f.location)

        if f.shacl_errors:
            print(f"ERROR: SHACL Validation failed for {f.location}:")
            print("\n".join(f.shacl_errors))

    if result.merged_skipped:
        print("WARNING: Skipping validation of merged documents due to previous errors")

    if result.merged_errors:
        print("ERROR: SHACL Validation failed on merged files:")
        print("\n".join(result.merged_errors))

    return 0 if result.valid else 1


def _resolve_version(
    current_version: Union[SpdxVersion, str, None],
) -> Optional[SpdxVersion]:
    """Normalize the version argument to a SpdxVersion or None (auto)."""
    if current_version is None:
        return None

    if isinstance(current_version, str):
        for v in SPDX_VERSIONS:
            if v.pretty == current_version:
                return v
        raise UnsupportedVersionError(f"Unknown SPDX version {current_version}")

    return current_version


def spdx3validate(
    json_files: Iterable[str],
    current_version: Union[SpdxVersion, str, None] = None,
    check_merged: bool = False,
    *,
    progress: Optional[ProgressFactory] = None,
) -> ValidationResult:
    """Validate SPDX 3 JSON documents.

    Args:
        json_files: Iterable of locations (URL, path, or "-" for stdin).
        current_version: A SpdxVersion, a version string like "3.0.1", or None
            to auto-detect from the documents' @context.
        check_merged: Also validate the merged graph of all documents.
        progress: Optional context-manager factory ``progress(text)`` yielding an
            object with ``.succeed()`` / ``.fail()`` (e.g. a halo spinner). Defaults
            to a silent no-op.

    Returns:
        ValidationResult describing per-file and merged outcomes. Truthy when valid.

    Raises:
        UnsupportedVersionError: Unknown version, or inputs mix incompatible versions.
        SchemaError: The SPDX schema is not usable.
        urllib.error.URLError: A schema/document URL could not be fetched.
    """
    report_progress: ProgressFactory = null_progress if progress is None else progress

    version: Optional[SpdxVersion] = _resolve_version(current_version)

    result = ValidationResult()
    files: List[Tuple[str, Any, Graph]] = []
    for j in json_files:
        with report_progress(f"Loading {j}") as spinner:
            s = read_location(j)
            d = json.loads(s)
            if "@context" not in d:
                spinner.fail()
                result.files.append(
                    FileResult(j, load_errors=[f"No @context found in {j}"])
                )
                continue

            doc_version = find_version(d["@context"])
            if doc_version is None:
                spinner.fail()
                raise UnsupportedVersionError(
                    f"{j} has unknown version @context {d['@context']}"
                )

            if version is None:
                version = doc_version
            elif version != doc_version:
                spinner.fail()
                raise UnsupportedVersionError(
                    f"{j} has incompatible version {doc_version.pretty}. "
                    f"Other documents are {version.pretty}"
                )

            graph = rdflib.Graph()
            graph.parse(data=s, format="json-ld")

            files.append((j, d, graph))
            spinner.succeed()

    if not files:
        # Nothing to do
        return result

    if version is None:
        # Unreachable: any document added to ``files`` set ``version``.
        raise Spdx3ValidateError("Could not determine SPDX version")

    with report_progress(f"Loading SPDX {version.pretty}") as spinner:
        with urllib.request.urlopen(version.schema_url) as f:
            schema = json.load(f)

        shacl_graph = rdflib.Graph()
        shacl_graph.parse(version.shacl_url)
        spinner.succeed()

    any_errors = False

    for fn, json_data, g in files:
        file_result = FileResult(fn)
        result.files.append(file_result)

        with report_progress(f"Validating schema for {fn}") as spinner:
            validator_cls = jsonschema.validators.validator_for(schema)

            try:
                validator_cls.check_schema(schema)
            except jsonschema.exceptions.SchemaError as e:
                spinner.fail()
                raise SchemaError(f"Invalid schema {version.schema_url}: {e}") from e

            validator = validator_cls(schema)
            json_errors: List[ValidationError] = list(validator.iter_errors(json_data))
            if json_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if json_errors:
            file_result.schema_errors = json_errors

        with report_progress(f"Checking SHACL for {fn}") as spinner:
            shacl_errors = check_graph(g, shacl_graph, version, True)
            if shacl_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if shacl_errors:
            file_result.shacl_errors = shacl_errors

        if not file_result.valid:
            any_errors = True

    if len(files) > 1 and check_merged:
        if not any_errors:
            with report_progress("Checking merged graph") as spinner:
                merged_g = rdflib.Graph()
                for _, _, g in files:
                    merged_g += g

                merged_errors = check_graph(merged_g, shacl_graph, version, False)
                if merged_errors:
                    spinner.fail()
                else:
                    spinner.succeed()

            if merged_errors:
                result.merged_errors = merged_errors
        else:
            result.merged_skipped = True

    return result

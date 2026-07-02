# SPDX-FileContributor: Joshua Watt
# SPDX-FileCopyrightText: 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

import argparse
import sys

import halo
import jsonschema
import rdflib

from .version import VERSION
from .spdx_versions import SPDX_VERSIONS
from .core import (
    Document,
    SpdxValidateError,
    UnknownVersionError,
    check_graph,
    load_validation_data,
    schema_validator,
    _resolve_version,
)


def load_cli_document(source):
    """Load a document from a path, URL, or ``"-"`` for standard input.

    Unlike :meth:`Document.load`, this also accepts ``"-"``, which is a
    command-line convention (not a library one) for reading from stdin.
    """
    if source == "-":
        return Document.from_text(source, sys.stdin.read())
    return Document.load(source)


def iter_validation_errors(err):
    if err.context:
        for e in err.context:
            yield e
            yield from iter_validation_errors(e)


def print_schema_error(err, filename, indent=0):
    def print_err(e, indent, fn=None, message=False):
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

        error_map = {}
        for e in iter_validation_errors(err):
            if isinstance(e, str):
                error_map[(tuple(e.absolute_path), e.message)] = e
            else:
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


def main(cmdline_args=None):
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

    return spdx3validate(args.json, current_version, args.check_merged, args.quiet)


def spdx3validate(json_files, current_version=None, check_merged=False, quiet=True):
    try:
        current_version = _resolve_version(current_version)
    except UnknownVersionError as e:
        print(str(e))
        return 1

    documents = []
    for j in json_files:
        with halo.Halo(f"Loading {j}", enabled=not quiet) as spinner:
            try:
                doc = load_cli_document(j)
            except SpdxValidateError as e:
                spinner.fail()
                print(str(e))
                return 1

            if current_version is None:
                current_version = doc.version
            elif current_version != doc.version:
                spinner.fail()
                print(
                    f"{j} has incompatible version {doc.version.pretty}. Other documents are {current_version.pretty}"
                )
                return 1

            documents.append(doc)
            spinner.succeed()

    if not documents:
        # Nothing to do
        return 0

    with halo.Halo(
        f"Loading SPDX {current_version.pretty}", enabled=not quiet
    ) as spinner:
        schema, shacl_graph = load_validation_data(current_version)
        spinner.succeed()

    errors = 0

    for doc in documents:
        with halo.Halo(
            f"Validating schema for {doc.source}", enabled=not quiet
        ) as spinner:
            try:
                validator = schema_validator(schema)
            except jsonschema.exceptions.SchemaError as e:
                spinner.fail(f"Invalid schema {current_version.schema_url}: {e}")
                return 1

            json_errors = list(validator.iter_errors(doc.data))
            if json_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if json_errors:
            print(f"ERROR: JSON Schema validation failed for {doc.source}:")
            for e in json_errors:
                print_schema_error(e, doc.source)
                errors += 1

        with halo.Halo(
            f"Checking SHACL for {doc.source}", enabled=not quiet
        ) as spinner:
            e = check_graph(doc.graph, shacl_graph, current_version, True)
            if e:
                spinner.fail()
            else:
                spinner.succeed()

        if e:
            print(f"ERROR: SHACL Validation failed for {doc.source}:")
            print("\n".join(e))
            errors += 1

    if len(documents) > 1 and check_merged:
        if not errors:
            with halo.Halo("Checking merged graph", enabled=not quiet) as spinner:
                merged_g = rdflib.Graph()
                for doc in documents:
                    merged_g += doc.graph

                e = check_graph(merged_g, shacl_graph, current_version, False)
                if e:
                    spinner.fail()
                else:
                    spinner.succeed()

            if e:
                print("ERROR: SHACL Validation failed on merged files:")
                print("\n".join(e))
                errors += 1
        else:
            print(
                "WARNING: Skipping validation of merged documents due to previous errors"
            )

    return 1 if errors else 0

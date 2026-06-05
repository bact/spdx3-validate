# Copyright (c) 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""SPDX spec versions and associated model/schema files."""

from typing import Callable, Iterator, NamedTuple, Optional, Tuple

from rdflib import RDF, Graph, URIRef
from rdflib.term import Node


class SpdxVersion(NamedTuple):
    context_url: str
    shacl_url: str
    schema_url: str
    pretty: str
    rdf_base: str
    get_imports: Callable[[Graph], Iterator[Node]]


def get_3_0_0_imports(graph: Graph) -> Iterator[Node]:
    rdf_base = URIRef("https://spdx.org/rdf/3.0.0/terms/")

    for doc in graph.subjects(RDF.type, rdf_base + "Core/SpdxDocument"):
        for i in graph.objects(doc, rdf_base + "Core/imports"):
            yield from graph.objects(i, rdf_base + "Core/externalSpdxId")


def get_3_0_1_imports(graph: Graph) -> Iterator[Node]:
    rdf_base = URIRef("https://spdx.org/rdf/3.0.1/terms/")

    for doc in graph.subjects(RDF.type, rdf_base + "Core/SpdxDocument"):
        for i in graph.objects(doc, rdf_base + "Core/import"):
            yield from graph.objects(i, rdf_base + "Core/externalSpdxId")


SPDX_VERSIONS: Tuple[SpdxVersion, ...] = (
    SpdxVersion(
        "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.0/spdx-model.ttl",
        "https://spdx.org/schema/3.0.0/spdx-json-schema.json",
        "3.0.0",
        "https://spdx.org/rdf/3.0.0/terms/",
        get_3_0_0_imports,
    ),
    SpdxVersion(
        "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        "3.0.1",
        "https://spdx.org/rdf/3.0.1/terms/",
        get_3_0_1_imports,
    ),
)


def find_version(context_url: str) -> Optional[SpdxVersion]:
    for s in SPDX_VERSIONS:
        if s.context_url == context_url:
            return s
    return None

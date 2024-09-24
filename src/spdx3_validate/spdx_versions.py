# Copyright (c) 2024 Joshua Watt
#
# SPDX-License-Identifier: MIT

from collections import namedtuple


SpdxVersion = namedtuple(
    "SpdxVersion",
    ["context_url", "shacl_url", "schema_url", "pretty", "rdf_base"],
)

SPDX_VERSIONS = (
    SpdxVersion(
        "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.0/spdx-model.ttl",
        "https://spdx.org/schema/3.0.0/spdx-json-schema.json",
        "3.0.0",
        "https://spdx.org/rdf/3.0.0/terms/",
    ),
    SpdxVersion(
        "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        "3.0.1",
        "https://spdx.org/rdf/3.0.1/terms/",
    ),
)


def find_version(context_url):
    for s in SPDX_VERSIONS:
        if s.context_url == context_url:
            return s
    return None

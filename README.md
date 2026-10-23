# SPDX 3 Validation Tool

Validates SPDX 3 documents

While standalone tools like `pyshacl` and `check-jsonschema` can be used to
validate SPDX 3 documents, there are a few context-aware checks that can be
useful. This includes:

1. Ignored SHACL errors for missing `spdxId`s if they are defined in an
   `ExternalMap`
2. Validation that any `spdxId` defined in an `ExternalMap` are _not_ present
   in the document
3. SHACL Validation of merged documents (in this way, if you reference an
   `spdxId` from an `ExternalMap` and then pass the document that provides that
   `spdxId`, the type can be validated)
4. (Hopefully) More useful JSON schema error output

## Installation

`spdx3-validate` can be installed using `pip`:

```shell
python3 -m pip install spdx3-validate
```

## Usage

Validate one or more documents (a path, a URL, or `-` for standard input):

```shell
spdx3-validate --json doc.spdx3.json
spdx3-validate --json sbom.spdx3.json --json external.spdx3.json
```

Run `spdx3-validate --help` for all options.

### Validating extensions

The SPDX 3 model cannot know about the classes and constraints of a custom
extension, so by default an extension's own properties are not checked. Pass
the extension's OWL ontology and SHACL shapes (any RDF format, as a path or a
URL) with `--shacl`, which may be given more than once:

```shell
spdx3-validate --shacl my-extension.ttl --json doc.spdx3.json
```

Each file is merged into both the SHACL shapes graph and the ontology graph
used for validation. The ontology must therefore contain the extension classes'
`rdfs:subClassOf` links to `Extension/Extension` (using the term IRIs of the
SPDX version being validated, e.g. `https://spdx.org/rdf/3.0.1/terms/`), so
that `sh:class` constraints resolve.

Only the RDFS/OWL axioms of the ontology are added to the data before
validation (pyshacl "inoculates" the data graph with them): resources typed as
RDFS/OWL classes or properties, triples such as `rdfs:subClassOf`,
`rdfs:domain` and `rdfs:range`, and deep copies of `owl:NamedIndividual`
resources. An extension's vocabulary individuals (e.g. the values of an
enumeration checked with `sh:class`) must therefore be typed
`owl:NamedIndividual` as well as with their class. `owl:imports` in a
`--shacl` file are not followed; pass each file with its own `--shacl`. The
same file given more than once is loaded once.

`--shacl` files are trusted input. Because they are merged with the SPDX model,
they can also weaken validation against SPDX itself, for example by
deactivating an SPDX shape (`sh:deactivated true`), by redefining SPDX terms,
or by declaring `owl:NamedIndividual` instances of SPDX classes, which are
copied into every validated document. A warning is printed (and
`spdx3_validate.ExtraShaclWarning` is emitted for library use) when a file has
statements about terms in an SPDX namespace, `owl:NamedIndividual` instances of
SPDX classes, or `sh:deactivated true`. Validation still runs with the file.
A file whose shapes are malformed (e.g. two `sh:maxCount` on one property) is
reported as an error.

When `--shacl` is given, every `extension` value must also have a type that is
`Extension/Extension` or derives from it in the SPDX model or the supplied
files. In other words, every extension type used in the document must then be
defined in a file passed with `--shacl` (or be an extension class of the SPDX
model itself, such as `CdxPropertiesExtension`); give one `--shacl` per
extension used. An extension whose type is unknown, for example because of a
typo in its type IRI, or is not an `Extension`, is then reported. A value that
the SPDX model already rejects as a class known not to be an `Extension` (e.g.
a `Person`) is reported once, by the model's own check. An extension value
given only as an IRI that is listed in an `ExternalMap` import is, like other
external references, not reported when its document is validated on its own.

Without `--shacl`, as in the SPDX 3.0.1 model itself, extension types are not
checked this way, since custom extension classes cannot be known in advance.
The SPDX 3.0.0 model already requires every `extension` value to be an
`Extension`, with or without `--shacl`, so for 3.0.0 documents this check is
not added again.

## Using as a library

`spdx3-validate` can also be used programmatically.
`validate()` takes a single source or an iterable of sources
(a path or a URL) and returns a `ValidationResult`:

```python
import spdx3_validate

result = spdx3_validate.validate("doc.spdx3.json")
if not result:
    print(result)  # prints the errors, one per line

# Or inspect the individual findings:
for error in result.errors:
    print(error)
```

- The SPDX version is detected from each document's `@context`;
  pass `version="X.Y"` to force one.
- Set `check_merged=True` to also validate the merged graph of several
  documents together.
- Pass `extra_shacl=["my-extension.ttl"]` to also validate against
  additional SHACL shapes / OWL ontologies, such as the definition of an
  extension (the library equivalent of `--shacl`).
- A document that cannot be loaded (missing `@context`, unknown version,
  incompatible versions) raises `spdx3_validate.SpdxValidateError`.

## Developing

Developing on `spdx3-validate` is best done using a virtual environment. You
can configure one and install spdx3-validate in editable mode with all
necessary development dependencies by running:

```shell
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## TODO

- Option to automatically download dependencies based on `locationHint`
- Offline validation?
- Cache downloaded context

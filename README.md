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

## Library usage

```python
from spdx3_validate import spdx3validate

# check single document
result = spdx3validate(["doc.json"])

# check a.json, b.json, and the merged document of a.json+b.json
result = spdx3validate(["a.json", "b.json"], check_merged=True)

if result:                       # truthy when valid
    print("valid")
else:
    for r in result.results:     # one Result per input
        print(r.shacl_errors)    # SHACL errors of each document
    print(result.shacl_errors)   # SHACL errors of the merged document
```

- **`spdx3validate(...)` returns a `MergedResult`** — **truthy when valid**.
- **`.results`** — list of **`Result`** (`.location`, `.load_errors`,
  `.schema_errors`, `.shacl_errors`, `.valid`).
- **`.shacl_errors`** — SHACL errors of the **merged document** (only with
  **`check_merged=True`**).
- **Raises** `UnsupportedVersionError` / `SchemaError` when validation can't run.

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

* Option to automatically download dependencies based on `locationHint`
* Offline validation?

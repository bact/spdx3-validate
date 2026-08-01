# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test the validate() library API and the spdx3validate() CLI entry point."""

import json
from pathlib import Path

import pytest

import spdx3_validate

DATA_DIR = Path(__file__).parent / "data"
VALID_DOC = DATA_DIR / "3.0.1" / "valid" / "package_sbom.json"
INVALID_DOC = DATA_DIR / "3.0.1" / "invalid" / "package_sbom_missing_creationinfo.json"


# --- Library API: validate() -------------------------------------------------


def test_validate_valid() -> None:
    """A known-valid document validates with no errors."""
    try:
        result = spdx3_validate.validate(str(VALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert result.valid
    assert bool(result) is True
    assert result.errors == []


def test_validate_invalid() -> None:
    """A known-invalid document reports attributed ValidationError objects."""
    try:
        result = spdx3_validate.validate(str(INVALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert not result.valid
    assert not result
    assert result.errors
    assert str(result)  # errors render as text
    for err in result.errors:
        assert isinstance(err, spdx3_validate.ValidationError)
        assert err.source == str(INVALID_DOC)
        assert err.kind in {"schema", "shacl"}
        assert err.message


def test_validate_no_sources_is_valid() -> None:
    """Validating nothing succeeds without touching the network."""
    result = spdx3_validate.validate([])
    assert result.valid
    assert result.errors == []


def test_load_nonexistent_file_raises_resource_not_found(
    tmp_path: Path,
) -> None:
    """Loading a non-existent document file raises ResourceNotFoundError."""
    missing_file = tmp_path / "does_not_exist.json"
    with pytest.raises(spdx3_validate.ResourceNotFoundError):
        spdx3_validate.Document.load(str(missing_file))


def test_validate_missing_context_raises(tmp_path: Path) -> None:
    """A document without an @context raises SpdxValidateError (no network)."""
    bad = tmp_path / "no_context.json"
    bad.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate(str(bad))


def test_validate_unknown_version_raises() -> None:
    """An unknown version string raises UnknownVersionError (no network)."""
    with pytest.raises(spdx3_validate.UnknownVersionError):
        spdx3_validate.validate([], version="9.9.9")


def test_error_and_result_rendering() -> None:
    """ValidationError / ValidationResult render as text (no network)."""
    err = spdx3_validate.ValidationError("a.json", "shacl", "boom")
    assert str(err) == "a.json [shacl]: boom"

    result = spdx3_validate.ValidationResult([err])
    assert not result
    assert not result.valid
    assert str(result) == "a.json [shacl]: boom"


def test_empty_result_is_valid_and_blank() -> None:
    """An empty ValidationResult is valid and renders as an empty string."""
    result = spdx3_validate.ValidationResult()
    assert result.valid
    assert bool(result) is True
    assert str(result) == ""


# --- CLI entry point: spdx3validate() (back-compat) --------------------------


def test_spdx3validate_is_callable() -> None:
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


def test_spdx3validate_valid() -> None:
    """A known-valid SPDX 3.0.1 document validates successfully."""
    try:
        rc = spdx3_validate.spdx3validate([str(VALID_DOC)])
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc == 0


def test_spdx3validate_invalid() -> None:
    """A known-invalid SPDX 3.0.1 document fails validation."""
    try:
        rc = spdx3_validate.spdx3validate([str(INVALID_DOC)])
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert rc != 0


# --- Offline validation tests ------------------------------------------------


def test_load_validation_data_local_files(tmp_path: Path) -> None:
    """load_validation_data loads schema & shacl from explicit file paths."""
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    shacl_file = tmp_path / "model.ttl"
    shacl_file.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )

    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]  # 3.0.1
    schema, graph = spdx3_validate.core.load_validation_data(
        version,
        schema_urls=[str(schema_file)],
        shacl_urls=[str(shacl_file)],
    )
    assert schema == {"type": "object"}
    assert len(graph) == 0


def test_document_from_text_local_context(tmp_path: Path) -> None:
    """Document.from_text uses local spdx-context.jsonld (no network)."""
    context_file = tmp_path / "spdx-context.jsonld"
    context_file.write_text(
        json.dumps({"@context": {"@vocab": "https://spdx.org/rdf/3.0.1/terms/"}}),
        encoding="utf-8",
    )

    doc_text = json.dumps(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@id": "http://spdx.example.com/test",
            "type": "CreationInfo",
        }
    )

    doc = spdx3_validate.Document.from_text(
        "test.json",
        doc_text,
        context_urls=[str(context_file)],
    )
    assert doc.version.pretty == "3.0.1"
    assert len(doc.graph) > 0


def test_load_validation_data_model_dir(tmp_path: Path) -> None:
    """load_validation_data resolves models from SPDX3VALIDATE_MODEL_DIR."""
    v_dir = tmp_path / "v3.0.1"
    v_dir.mkdir(parents=True)

    schema_file = v_dir / "spdx-json-schema.json"
    schema_file.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    shacl_file = v_dir / "spdx-model.ttl"
    shacl_file.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )

    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]  # 3.0.1
    schema, graph = spdx3_validate.core.load_validation_data(
        version,
        model_dir=str(tmp_path),
    )
    assert schema == {"type": "object"}
    assert len(graph) == 0


def test_strict_precedence_cli_missing_file_raises(tmp_path: Path) -> None:
    """If CLI specifies a file path that does not exist, fail immediately."""
    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]
    bad_schema = tmp_path / "nonexistent.json"
    with pytest.raises(
        spdx3_validate.ResourceNotFoundError,
        match="Specified schema file does not exist",
    ) as exc_info:
        spdx3_validate.core.load_validation_data(
            version,
            schema_urls=[str(bad_schema)],
        )
    assert isinstance(exc_info.value, spdx3_validate.SpdxValidateError)
    assert isinstance(exc_info.value, FileNotFoundError)


def test_strict_precedence_model_dir_missing_file_raises(
    tmp_path: Path,
) -> None:
    """If model_dir is set but required file is missing, fail immediately."""
    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]
    empty_model_dir = tmp_path / "models"
    empty_model_dir.mkdir()
    with pytest.raises(
        spdx3_validate.ResourceNotFoundError,
        match="Schema file spdx-json-schema.json not found in",
    ) as exc_info:
        spdx3_validate.core.load_validation_data(
            version,
            model_dir=str(empty_model_dir),
        )
    assert isinstance(exc_info.value, spdx3_validate.SpdxValidateError)
    assert isinstance(exc_info.value, FileNotFoundError)


def test_cli_multiple_schema_shapes_warning(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """CLI prints warnings when multiple --schema/--shapes options given."""
    from spdx3_validate.main import main

    schema1 = tmp_path / "schema1.json"
    schema2 = tmp_path / "schema2.json"
    shapes1 = tmp_path / "shapes1.ttl"
    shapes2 = tmp_path / "shapes2.ttl"

    schema1.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    schema2.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    shapes1.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )
    shapes2.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )

    rc = main(
        [
            "-j",
            str(VALID_DOC),
            "--schema",
            str(schema1),
            "--schema",
            str(schema2),
            "--shapes",
            str(shapes1),
            "--shapes",
            str(shapes2),
        ]
    )
    assert rc == 0

    captured = capsys.readouterr()
    assert "WARNING: Multiple --schema options are not supported yet." in captured.err
    assert "WARNING: Multiple --shapes options are not supported yet." in captured.err

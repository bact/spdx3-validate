# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Validator: equivalence with the one-shot path, isolation, reload, pre-release."""

import json
import re
import threading
import time
import urllib.error
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

import pytest
import rdflib
from rdflib.compare import isomorphic

import spdx3_validate
from spdx3_validate import core
from spdx3_validate.spdx_versions import SPDX_VERSIONS

V = SPDX_VERSIONS[1]  # 3.0.1

PFX = """@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix core: <https://spdx.org/rdf/3.0.1/terms/Core/> .
"""
THING_NAME = "core:Thing a owl:Class, sh:NodeShape ; sh:property [ sh:path core:name ; sh:minCount 1 ] ."
SCHEMA = {"type": "object", "properties": {"@graph": {"type": "array"}}}
GOOD = [{"type": "Thing", "spdxId": "http://ex/a", "name": "x"}]
SHACL_BAD = [{"type": "Thing", "spdxId": "http://ex/a"}]  # no name
SCHEMA_BAD: Any = {}  # "@graph" must be an array

MakeModel = Callable[..., str]
MakeDoc = Callable[..., str]


@pytest.fixture
def make_model(tmp_path: Path) -> MakeModel:
    """Write v3.0.0 and v3.0.1 model files; return the model dir."""
    count = [0]

    def make(shapes: str = THING_NAME, schema: Optional[Dict[str, Any]] = None) -> str:
        count[0] += 1
        root = tmp_path / f"models{count[0]}"
        for v in ("3.0.0", "3.0.1"):
            d = root / f"v{v}"
            d.mkdir(parents=True)
            vocab = f"https://spdx.org/rdf/{v}/terms/Core/"
            ctx = {"@vocab": vocab, "type": "@type", "spdxId": "@id"}
            (d / "spdx-context.jsonld").write_text(json.dumps({"@context": ctx}))
            (d / "spdx-json-schema.json").write_text(json.dumps(schema or SCHEMA))
            ttl = PFX.replace("3.0.1", v) + shapes.replace("3.0.1", v)
            (d / "spdx-model.ttl").write_text(ttl)
        return str(root)

    return make


@pytest.fixture
def make_doc(tmp_path: Path) -> MakeDoc:
    """Write a document with the given @graph; return its path."""
    count = [0]

    def make(graph: List[Dict[str, Any]], version: str = "3.0.1") -> str:
        count[0] += 1
        ctx = f"https://spdx.org/rdf/{version}/spdx-context.jsonld"
        path = tmp_path / f"doc{count[0]}.json"
        path.write_text(json.dumps({"@context": ctx, "@graph": graph}))
        return str(path)

    return make


def _norm(result: Any, ordered: bool = False) -> List[Tuple[str, str, str]]:
    # Blank-node ids differ between runs.
    out = [
        (e.source, e.kind, re.sub(r"_:\w+", "_:b", e.message)) for e in result.errors
    ]
    return out if ordered else sorted(out)


def _reference(
    paths: List[str], md: str, merged: bool, ordered: bool = False
) -> List[Tuple[str, str, str]]:
    """The pre-Validator pipeline, built from public pieces."""
    docs = [core.Document.load(p, model_dir=md) for p in paths]
    schema, shacl = core.load_validation_data(V, model_dir=md)
    val = core.schema_validator(schema)
    out = []
    for d in docs:
        out += [core._schema_error(d.source, e) for e in val.iter_errors(d.data)]
        out += [
            core.ValidationError(d.source, "shacl", m)
            for m in core.check_graph(d.graph, shacl, V, True)
        ]
    if merged and len(docs) > 1 and not out:
        g = rdflib.Graph()
        for d in docs:
            g += d.graph
        out += [
            core.ValidationError("(merged)", "shacl", m)
            for m in core.check_graph(g, shacl, V, False)
        ]
    return _norm(core.ValidationResult(out), ordered)


@pytest.mark.parametrize(
    "graphs",
    [[GOOD], [SHACL_BAD], [SCHEMA_BAD], [GOOD, SHACL_BAD], [GOOD, GOOD]],
    ids=["valid", "shacl_bad", "schema_bad", "pair", "pair_merged"],
)
def test_matches_reference_pipeline(graphs: Any, make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """Validator, validate() and the old pipeline give the same findings."""
    md = make_model()
    paths = [make_doc(g) for g in graphs]
    got = spdx3_validate.Validator(model_dir=md).validate(paths, check_merged=True)
    assert _norm(got) == _reference(paths, md, True)
    assert [(e.source, e.kind) for e in got.errors] == [
        (s, k) for s, k, _ in _reference(paths, md, True, ordered=True)
    ]
    assert _norm(got) == _norm(spdx3_validate.validate(paths, model_dir=md, check_merged=True))  # fmt: skip


def test_no_error_leak_between_runs(make_model: MakeModel, make_doc: MakeDoc) -> None:
    """Reusing one Validator never carries errors from one run to the next."""
    v = spdx3_validate.Validator(model_dir=make_model())
    bad, good = make_doc(SHACL_BAD), make_doc(GOOD)
    assert not v.validate(bad)
    assert v.validate(good)
    assert {e.source for e in v.validate([bad, good]).errors} == {bad}


def test_separate_model_dirs_isolated(make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """Validators on different model dirs never share loaded data."""
    v1 = spdx3_validate.Validator(model_dir=make_model())
    v2 = spdx3_validate.Validator(model_dir=make_model(shapes="core:Thing a owl:Class ."))  # fmt: skip
    doc = make_doc(SHACL_BAD)
    for _ in range(2):
        assert not v1.validate(doc)
        assert v2.validate(doc)
    assert v1.load("3.0.1").shacl_graph is not v2.load("3.0.1").shacl_graph


def test_reload_picks_up_edit(make_model: MakeModel, make_doc: MakeDoc) -> None:
    """Edited model files are seen only after reload()."""
    md = make_model()
    a, b = (spdx3_validate.Validator(model_dir=md) for _ in range(2))
    doc = make_doc(GOOD)
    assert a.validate(doc) and b.validate(doc)
    ttl = Path(md) / "v3.0.1" / "spdx-model.ttl"
    ttl.write_text(ttl.read_text() + "\ncore:Thing sh:property [ sh:path core:missing ; sh:minCount 1 ] .")  # fmt: skip
    a.reload()
    assert not a.validate(doc)
    assert b.validate(doc)


def test_lazy_no_io_until_needed(tmp_path: Path) -> None:
    """Construction and empty validation touch no files."""
    v = spdx3_validate.Validator("3.0.1", model_dir=str(tmp_path / "nope"))
    assert v.validate([]).valid
    with pytest.raises(spdx3_validate.ResourceNotFoundError):
        v.load()
    with pytest.raises(spdx3_validate.UnknownVersionError):
        spdx3_validate.Validator("9.9.9")
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.Validator().load()


@pytest.mark.parametrize("same_call", [True, False], ids=["same_call", "across_calls"])
def test_auto_version_mismatch_raises(same_call: bool, make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """With auto-detect, a document of another version is rejected."""
    v = spdx3_validate.Validator(model_dir=make_model())
    d1, d2 = make_doc(GOOD), make_doc(GOOD, version="3.0.0")
    with pytest.raises(spdx3_validate.SpdxValidateError, match="incompatible version"):
        if same_call:
            v.validate([d1, d2])
        else:
            v.validate(d1)
            v.validate(d2)


def test_load_other_version_than_pinned_raises(make_model: MakeModel) -> None:
    """load() must not replace a pinned version, before or after the first load."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model())
    v.load()
    with pytest.raises(spdx3_validate.SpdxValidateError, match="not 3.0.0"):
        v.load("3.0.0")
    assert v.version is V


def test_load_document_explicit_context(make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """An explicit context file is used, and a missing one is reported."""
    md, path = make_model(), make_doc(GOOD)
    ctx = Path(md) / "v3.0.1" / "spdx-context.jsonld"
    v = spdx3_validate.Validator(context_urls=[str(ctx)])
    assert len(v.load_document(path).graph) > 0
    with pytest.raises(spdx3_validate.ResourceNotFoundError):
        spdx3_validate.Validator(context_urls=[str(ctx) + ".nope"]).load_document(path)  # fmt: skip


def test_concurrent_first_loads_of_different_versions(monkeypatch: pytest.MonkeyPatch, make_model: MakeModel) -> None:  # fmt: skip
    """A thread waiting on the load lock must still reject a different version."""
    started, release = threading.Event(), threading.Event()
    orig = core.Validator._load_model

    def slow(self: Any, version: Any) -> Any:
        started.set()
        release.wait(5)
        return orig(self, version)

    monkeypatch.setattr(core.Validator, "_load_model", slow)
    v = spdx3_validate.Validator(model_dir=make_model())
    first = threading.Thread(target=v.load, args=("3.0.1",))
    first.start()
    started.wait(5)
    errors: List[BaseException] = []

    def second() -> None:
        try:
            v.load("3.0.0")
        except spdx3_validate.SpdxValidateError as e:
            errors.append(e)

    t = threading.Thread(target=second)
    t.start()
    time.sleep(0.2)  # let it block on the lock
    release.set()
    first.join()
    t.join()
    assert len(errors) == 1 and v.version is V


MAX_ONE_NAME = THING_NAME.replace("sh:minCount 1", "sh:minCount 1 ; sh:maxCount 1")


def test_merged_check_finds_cross_document_errors(make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """Each document is valid alone; only the merged graph has two names."""
    md = make_model(shapes=MAX_ONE_NAME)
    a = make_doc(GOOD)
    b = make_doc([{**GOOD[0], "name": "y"}])
    v = spdx3_validate.Validator(model_dir=md)
    assert v.validate([a, b])
    merged = v.validate([a, b], check_merged=True)
    assert [e.source for e in merged.errors] == ["(merged)"]
    assert spdx3_validate.spdx3validate([a, b], model_dir=md, quiet=True, check_merged=True) == 1  # fmt: skip
    assert spdx3_validate.spdx3validate([a, b], model_dir=md, quiet=True) == 0


def test_invalid_schema_and_missing_model_reported(make_model: MakeModel, make_doc: MakeDoc, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """A malformed schema or missing model file is an SpdxValidateError and CLI rc 1."""
    bad = make_model(schema={"type": 5})
    with pytest.raises(spdx3_validate.SpdxValidateError, match="Invalid schema"):
        spdx3_validate.Validator("3.0.1", model_dir=bad).load()
    doc = make_doc(GOOD)
    assert spdx3_validate.spdx3validate([doc], model_dir=bad, quiet=True) == 1
    ctx_only = tmp_path / "ctx_only" / "v3.0.1"
    ctx_only.mkdir(parents=True)
    (ctx_only / "spdx-context.jsonld").write_text((Path(make_model()) / "v3.0.1" / "spdx-context.jsonld").read_text())  # fmt: skip
    assert spdx3_validate.spdx3validate([doc], model_dir=str(ctx_only.parent), quiet=True) == 1  # fmt: skip
    assert "not found" in capsys.readouterr().out


def test_shapes_graph_fixed_after_load(make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """pyshacl's system triples are pre-added, so its re-adds change nothing."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model())
    graph = v.load().shacl_graph
    before = set(graph)
    v.validate([make_doc(SHACL_BAD), make_doc(GOOD)])
    assert set(graph) == before


def test_built_once(monkeypatch: pytest.MonkeyPatch, make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """Schema validator and context are built/read once per Validator and per CLI run."""
    calls = {"schema": 0, "ctx": 0}
    orig_sv, orig_rc = core.schema_validator, core._read_context

    def sv(schema: Any) -> Any:
        calls["schema"] += 1
        return orig_sv(schema)

    def rc(loc: str) -> Any:
        calls["ctx"] += 1
        return orig_rc(loc)

    monkeypatch.setattr(core, "schema_validator", sv)
    monkeypatch.setattr(core, "_read_context", rc)
    md = make_model()
    docs = [make_doc(GOOD) for _ in range(3)]
    v = spdx3_validate.Validator(model_dir=md)
    v.validate(docs)
    v.validate(docs[0])
    assert calls == {"schema": 1, "ctx": 1}
    calls.update(schema=0, ctx=0)
    assert spdx3_validate.spdx3validate(docs, model_dir=md, quiet=True) == 0
    assert calls == {"schema": 1, "ctx": 1}


def test_reload_during_context_read_drops_stale_context(monkeypatch: pytest.MonkeyPatch, make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """A context fetched before reload() must not repopulate the cache after it."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model())
    orig = core._read_context

    def read_then_reload(location: str) -> Any:
        ctx = orig(location)
        v.reload()  # a reload lands while the read is in flight
        return ctx

    monkeypatch.setattr(core, "_read_context", read_then_reload)
    v.load_document(make_doc(GOOD))
    assert v._contexts == {}


def test_context_cache_graph_equal(make_model: MakeModel, make_doc: MakeDoc) -> None:
    """A cached context yields the same graph as an uncached load."""
    md, path = make_model(), make_doc(GOOD)
    v = spdx3_validate.Validator(model_dir=md)
    v.load_document(path)
    assert isomorphic(v.load_document(path).graph, core.Document.load(path, model_dir=md).graph)  # fmt: skip


def test_thread_shared(
    monkeypatch: pytest.MonkeyPatch, make_model: MakeModel, make_doc: MakeDoc
) -> None:
    """Threads sharing a fresh Validator build the model once and get correct results."""
    built = []
    orig = core.schema_validator

    def counting(schema: Any) -> Any:
        built.append(1)
        return orig(schema)

    monkeypatch.setattr(core, "schema_validator", counting)
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model())
    docs = [make_doc(GOOD if i % 2 else SHACL_BAD) for i in range(16)]
    with ThreadPoolExecutor(4) as ex:
        results = list(ex.map(v.validate, docs))
    assert [bool(r) for r in results] == [bool(i % 2) for i in range(16)]
    assert len(built) == 1


# --- pre-release detection ----------------------------------------------------


def _onto(props: str) -> rdflib.Graph:
    ttl = PFX + f"@prefix ex: <http://ex/> .\n<http://ex/o> a owl:Ontology ; {props} ."
    return rdflib.Graph().parse(data=ttl, format="turtle")


S2C = "<https://jpewdev.github.io/shacl2code/schema#isPreRelease>"
PRE_SHAPES = THING_NAME + f"\n<http://ex/o> a owl:Ontology ; {S2C} true ."
SEMIC = "<http://publications.europa.eu/resource/authority/dataset-status/"
ADMS = "<http://www.w3.org/ns/adms#status>"
VS = "<http://www.w3.org/2003/06/sw-vocab-status/ns#term_status>"
PRE_CASES = [
    (f"{S2C} true", None, True),
    (f'{S2C} false ; {VS} "testing"', None, False),
    (f"{ADMS} {SEMIC}DEVELOP>", None, True),
    (
        f"{ADMS} {SEMIC}COMPLETED> ; <http://purl.org/ontology/bibo/status> <http://purl.org/ontology/bibo/status/draft>",
        None,
        False,
    ),  # fmt: skip
    (f"{ADMS} <http://purl.org/adms/status/UnderDevelopment>", None, True),
    (f"{ADMS} <http://purl.org/adms/status/Completed>", None, False),
    (
        "<http://purl.org/ontology/bibo/status> <http://purl.org/ontology/bibo/status/draft>",
        None,
        True,
    ),  # fmt: skip
    ('<http://schema.org/creativeWorkStatus> "Draft"', None, True),
    ('<https://schema.org/creativeWorkStatus> "Incomplete"', None, True),
    ('<http://schema.org/creativeWorkStatus> "Published"', None, False),
    (f'{VS} "unstable"', None, True),
    *(
        (f'owl:versionInfo "{v}"', None, True)
        for v in (
            "3.1-rc1",
            "3.1-dev",
            "1.0.0.alpha",
            "0.7.1",
            "1.0.0+build",
            "3.1+abc",
        )
    ),  # fmt: skip
    *((f'owl:versionInfo "{v}"', None, False) for v in ("3.0.1", "2024-01-15")),
    *((f'owl:versionInfo "{v}"', None, True) for v in ("v0.1", "0", "v3.1-rc1")),
    *((f'owl:versionInfo "{v}"', None, False) for v in ("1.0", "10.0.1")),
    (f'{S2C} "false"', None, False),
    ("owl:versionIRI ex:o", None, False),
    (f"{S2C} true", False, False),
    ('owl:versionInfo "3.0.1"', True, True),
]


@pytest.mark.parametrize("props,override,expected", PRE_CASES)
def test_pre_release_detection(props: str, override: Optional[bool], expected: bool) -> None:  # fmt: skip
    """Each shacl2code precedence level, plus the explicit override."""
    assert core._is_pre_release(_onto(props), override) is expected


def test_pre_release_other_shapes() -> None:
    """No ontology node is stable; any pre-release ontology node wins."""
    assert core._is_pre_release(rdflib.Graph()) is False
    g = _onto('owl:versionInfo "3.0.1"')
    g.add((rdflib.URIRef("http://ex/o2"), rdflib.RDF.type, rdflib.OWL.Ontology))
    g.add((rdflib.URIRef("http://ex/o2"), rdflib.OWL.versionInfo, rdflib.Literal("3.1-rc1")))  # fmt: skip
    assert core._is_pre_release(g) is True


def test_pre_release_model_warns(make_model: MakeModel) -> None:
    """A pre-release model issues a FutureWarning on load."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model(shapes=PRE_SHAPES))
    with pytest.warns(FutureWarning, match="pre-release.*reload"):
        v.load()
    assert v.is_pre_release is True


def test_stable_model_is_silent(make_model: MakeModel) -> None:
    """A stable model issues no warning."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model())
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert v.is_pre_release is False


@pytest.mark.parametrize("entry", ["validate_fn", "validate", "load", "reload", "prop"])
def test_warning_points_at_caller(entry: str, make_model: MakeModel, make_doc: MakeDoc) -> None:  # fmt: skip
    """FutureWarning is attributed to the calling file on every entry point."""
    md, doc = make_model(shapes=PRE_SHAPES), make_doc(GOOD)
    v = spdx3_validate.Validator("3.0.1", model_dir=md)
    if entry == "reload":
        with pytest.warns(FutureWarning):
            v.load()
    calls: Dict[str, Callable[[], Any]] = {
        "validate_fn": lambda: spdx3_validate.validate(doc, model_dir=md),
        "validate": lambda: v.validate(doc),
        "load": v.load,
        "reload": v.reload,
        "prop": lambda: v.is_pre_release,
    }
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        calls[entry]()
    assert [x.filename for x in w if x.category is FutureWarning] == [__file__]


def test_pre_release_override_suppresses_warning(make_model: MakeModel) -> None:
    """pre_release=False silences the warning and is reported."""
    v = spdx3_validate.Validator("3.0.1", model_dir=make_model(shapes=PRE_SHAPES), pre_release=False)  # fmt: skip
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert v.is_pre_release is False


@pytest.mark.parametrize("action", ["ignore", "error"])
def test_cli_honours_warning_filters(action: Literal["ignore", "error"], make_model: MakeModel, make_doc: MakeDoc, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """User warning filters apply to the CLI's pre-release notice."""
    md = make_model(shapes=PRE_SHAPES)
    with warnings.catch_warnings():
        warnings.simplefilter(action, FutureWarning)
        if action == "error":
            with pytest.raises(FutureWarning):
                spdx3_validate.spdx3validate([make_doc(GOOD)], model_dir=md, quiet=True)
        else:
            assert spdx3_validate.spdx3validate([make_doc(GOOD)], model_dir=md, quiet=True) == 0  # fmt: skip
    assert "WARNING" not in capsys.readouterr().err


def test_cli_prints_pre_release_once(make_model: MakeModel, make_doc: MakeDoc, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """The CLI warns once on stderr and keeps its exit code."""
    md = make_model(shapes=THING_NAME + f"\n<http://ex/o> a owl:Ontology ; {S2C} true .")  # fmt: skip
    rc = spdx3_validate.spdx3validate([make_doc(GOOD), make_doc(GOOD)], model_dir=md, quiet=True)  # fmt: skip
    assert rc == 0
    err = capsys.readouterr().err
    assert err.count("pre-release") == 1
    assert "reload" not in err  # a CLI run always re-reads the model


def test_real_model_matches_validate() -> None:
    """Real 3.0.1 model: Validator and validate() agree (network, skipped offline)."""
    data = Path(__file__).parent / "data" / "3.0.1"
    paths = [str(data / "valid/package_sbom.json"), str(data / "invalid/package_sbom_missing_creationinfo.json")]  # fmt: skip
    try:
        a = spdx3_validate.Validator().validate(paths)
        b = spdx3_validate.validate(paths)
    except urllib.error.URLError as e:
        pytest.skip(f"network unavailable: {e}")
    assert _norm(a) == _norm(b) and not a

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_sink.records import problems, schema

from .conftest import event, record


def test_the_events_producers_send_meet_the_schema() -> None:
    assert problems(event()) == []
    assert problems({**event(), "type": "vrixel.audit.v1"}) == []  # producers from before the rename


@pytest.mark.parametrize(
    ("change", "where"),
    [
        ({"outcome": "ok"}, "data/outcome"),
        ({"actor": {"id": "x", "type": "robot"}}, "data/actor/type"),
        ({"data_class": "secret"}, "data/data_class"),
        ({"patient_name": "Jane"}, "data"),  # a field value where only ids belong
        ({"trace_id": "not-hex"}, "data/trace_id"),
    ],
)
def test_an_event_that_drifts_from_the_schema_is_a_reject(change: dict[str, object], where: str) -> None:
    bad = event(**change)  # type: ignore[arg-type]
    assert any(p.startswith(where) for p in problems(bad))
    with pytest.raises(ValueError, match="breaks the schema"):
        record(1, bad).event()


def test_the_schema_is_versioned_and_loads() -> None:
    s = schema()
    assert s["x-version"] == "1.0.0" and s["properties"]["type"]["const"] == "valxel.audit.v1"
    json.dumps(s)


def test_a_product_holds_records_to_its_own_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_sink.records as records

    product = json.loads(json.dumps(schema()))
    product["$defs"]["data"]["required"].append("reason")  # this product wants a reason on every record
    f = tmp_path / "emr.audit.schema.json"
    f.write_text(json.dumps(product))
    monkeypatch.setenv("AUDIT_SINK_SCHEMA_FILE", str(f))
    records._validator.cache_clear()
    try:
        bare = event()
        del bare["data"]["reason"]
        assert any("reason" in p for p in problems(bare))
        assert problems(event()) == []
    finally:
        monkeypatch.delenv("AUDIT_SINK_SCHEMA_FILE")
        records._validator.cache_clear()
    bare = event()
    del bare["data"]["reason"]
    assert problems(bare) == []  # the platform's default doesn't require it

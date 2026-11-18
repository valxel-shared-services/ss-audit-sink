from __future__ import annotations

import json

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

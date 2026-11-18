"""What the sink reads from Kafka: a message's coordinates and its audit event."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

EVENT_TYPE = "valxel.audit.v1"
# Producers from before the Vrixel -> Valxel rename still send the old type; both are the same schema.
EVENT_TYPES = (EVENT_TYPE, "vrixel.audit.v1")
# The event's contract. The sink owns it; every producer keeps a byte-identical copy at
# contracts/audit/valxel.audit.v1.schema.json and tests its events against it, and the Valxel SDLC
# checks daily that each copy is this one (its template contract, audit_event).
SCHEMA_FILE = "valxel.audit.v1.schema.json"


def schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        resources.files("audit_sink").joinpath(SCHEMA_FILE).read_text(encoding="utf-8")
    )
    return loaded


@cache
def _validator() -> Any:
    from jsonschema import Draft202012Validator

    return Draft202012Validator(schema())


def problems(event: Any) -> list[str]:
    """Where an event breaks the schema, one line each (empty when it doesn't)."""
    if isinstance(event, dict) and event.get("type") in EVENT_TYPES:
        event = {**event, "type": EVENT_TYPE}
    out = []
    for err in sorted(_validator().iter_errors(event), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "event"
        out.append(f"{where}: {err.message}"[:200])
    return out


@dataclass(frozen=True)
class Record:
    topic: str
    partition: int
    offset: int
    timestamp_ms: int
    key: str
    raw: bytes

    def event(self) -> dict[str, Any]:
        """The audit event, or ValueError if this isn't one."""
        try:
            e = json.loads(self.raw)
        except ValueError as exc:
            raise ValueError(f"not JSON: {exc}") from exc
        if not isinstance(e, dict) or e.get("type") not in EVENT_TYPES or not isinstance(e.get("data"), dict):
            raise ValueError(f"not a {EVENT_TYPE} event")
        for f in ("id", "time"):
            if not e.get(f):
                raise ValueError(f"missing {f}")
        try:
            datetime.fromisoformat(str(e["time"]))
        except ValueError as exc:
            raise ValueError("time is not an ISO 8601 timestamp") from exc
        found = problems(e)
        if found:
            raise ValueError("breaks the schema: " + "; ".join(found[:3]))
        return e

    def line(self) -> dict[str, Any]:
        """The record as one line of an archive file: the event as sent, with where it came from."""
        try:
            value: Any = json.loads(self.raw)
        except ValueError:
            value = self.raw.decode("utf-8", errors="replace")
        return {
            "topic": self.topic,
            "partition": self.partition,
            "offset": self.offset,
            "timestamp": datetime.fromtimestamp(self.timestamp_ms / 1000, UTC).isoformat(),
            "key": self.key,
            "value": value,
        }

    @classmethod
    def from_line(cls, line: dict[str, Any]) -> Record:
        v = line["value"]
        raw = v.encode() if isinstance(v, str) else json.dumps(v, separators=(",", ":")).encode()
        ts = int(datetime.fromisoformat(line["timestamp"]).timestamp() * 1000)
        return cls(line["topic"], int(line["partition"]), int(line["offset"]), ts, line.get("key") or "", raw)

    @classmethod
    def from_message(cls, msg: Any) -> Record:
        _, ts = msg.timestamp()
        key = msg.key()
        return cls(
            msg.topic(),
            msg.partition(),
            msg.offset(),
            int(ts or 0),
            key.decode("utf-8", errors="replace") if key else "",
            msg.value() or b"",
        )

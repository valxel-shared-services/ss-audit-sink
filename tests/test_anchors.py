"""Chain heads anchored under Object Lock (review finding 7): tampering that recomputes the hashes."""

from __future__ import annotations

import json
import threading
from typing import Any

import boto3
import pytest
from moto import mock_aws

from audit_sink import anchors, postgres
from audit_sink.chain import GENESIS, link
from audit_sink.cli import main
from audit_sink.postgres import PostgresSink

from .conftest import record, url_of


def sink(db: Any) -> PostgresSink:
    postgres.setup(db)
    return PostgresSink(db)


def rewrite_and_recompute(db: Any, offset: int) -> None:
    """What the tables' owner could do: change a row, then redo every hash after it."""
    db.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_change")
    db.execute(
        """UPDATE audit_events SET event = jsonb_set(event, '{data,actor,id}', '"someone-else"')"""
        """ WHERE "offset" = %s""",
        (offset,),
    )
    prev = GENESIS
    rows = db.execute('SELECT "offset", event FROM audit_events ORDER BY "offset"').fetchall()
    for off, event in rows:
        h = link(prev, "audit.v1", 0, int(off), event)
        db.execute('UPDATE audit_events SET prev_hash = %s, hash = %s WHERE "offset" = %s', (prev, h, off))
        prev = h


@pytest.fixture
def store() -> Any:
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="emr-audit", ObjectLockEnabledForBucket=True)
        yield anchors.Anchors(s3, "emr-audit", retention_days=30)


def test_a_recomputed_rewrite_passes_the_chain_but_not_the_anchors(db: Any, store: Any) -> None:
    sink(db).write([record(i) for i in range(4)])
    assert anchors.anchor_all(db, store) == 1 and anchors.anchor_all(db, store) == 0  # unmoved: no new anchor
    rewrite_and_recompute(db, 3)
    assert postgres.verify(db, "audit.v1", 0)[1] is None  # the chain alone can't tell
    [problem] = anchors.check(db, store, "audit.v1", 0)
    assert "offset 3" in problem and "rewritten" in problem


def test_removing_an_anchored_row_shows(db: Any, store: Any) -> None:
    sink(db).write([record(i) for i in range(3)])
    anchors.anchor_all(db, store)
    db.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_change")
    db.execute('DELETE FROM audit_events WHERE "offset" = 2')
    assert "is gone" in next(anchors.check(db, store, "audit.v1", 0))


def test_anchors_are_object_locked_and_named_by_partition(db: Any, store: Any) -> None:
    sink(db).write([record(0), record(0, partition=1)])
    assert anchors.anchor_all(db, store) == 2
    keys = [o["Key"] for o in store.s3.list_objects_v2(Bucket="emr-audit")["Contents"]]
    assert {k.rsplit("/", 1)[0] for k in keys} == {
        "anchors/audit.v1/partition=0",
        "anchors/audit.v1/partition=1",
    }
    obj = store.s3.get_object(Bucket="emr-audit", Key=keys[0])
    assert obj["ObjectLockMode"] == "COMPLIANCE" and obj["ObjectLockRetainUntilDate"]
    body = json.loads(obj["Body"].read())
    assert set(body) == {"topic", "partition", "offset", "hash", "at"}
    with pytest.raises(ValueError):
        store.put({"topic": "../x", "partition": 0, "offset": 0, "hash": "h"})


def test_the_loop_anchors_and_survives_a_failure(db: Any, store: Any) -> None:
    sink(db).write([record(0)])
    stop, calls = threading.Event(), []

    def conn() -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database away")
        if len(calls) == 3:
            stop.set()
        import psycopg

        return psycopg.connect(url_of(db), autocommit=True)

    anchors.loop(stop, conn, store, 0.01)
    assert len(calls) >= 2 and store.list("audit.v1", 0)


def test_the_cli_anchors_and_verify_checks_against_the_anchors(
    db: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setenv("AUDIT_SINK_DATABASE_URL", url_of(db))
    monkeypatch.setenv("AUDIT_SINK_ARCHIVE_BUCKET", "emr-audit")
    monkeypatch.setenv("AUDIT_SINK_ARCHIVE_REGION", "us-east-1")
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket="emr-audit", ObjectLockEnabledForBucket=True
        )
        assert main(["setup"]) == 0
        sink(db).write([record(i) for i in range(3)])
        assert main(["anchor"]) == 0 and "anchored 1 partition heads" in capsys.readouterr().out
        assert main(["verify"]) == 0 and '"anchors": "consistent"' in capsys.readouterr().out
        rewrite_and_recompute(db, 2)
        assert main(["verify"]) == 1 and "rewritten" in capsys.readouterr().out


def test_without_a_bucket_there_is_nowhere_to_anchor(
    db: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setenv("AUDIT_SINK_DATABASE_URL", url_of(db))
    monkeypatch.delenv("AUDIT_SINK_ARCHIVE_BUCKET", raising=False)
    assert main(["anchor"]) == 1 and "nowhere to anchor" in capsys.readouterr().out

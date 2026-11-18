from __future__ import annotations

from typing import Any

import boto3
import pytest
from moto import mock_aws

from audit_sink import app as app_mod
from audit_sink.archive import ArchiveSink
from audit_sink.cli import main
from audit_sink.settings import Settings

from .conftest import record, url_of


def env(monkeypatch: pytest.MonkeyPatch, db: Any) -> None:
    monkeypatch.setenv("AUDIT_SINK_DATABASE_URL", url_of(db))
    monkeypatch.setenv("AUDIT_SINK_ARCHIVE_BUCKET", "emr-audit")
    monkeypatch.setenv("AUDIT_SINK_ARCHIVE_REGION", "us-east-1")


def test_setup_restore_and_verify(db: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    env(monkeypatch, db)
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="emr-audit", ObjectLockEnabledForBucket=True)
        a = ArchiveSink(s3, "emr-audit", batch_events=2)
        a.add([record(i) for i in range(3)] + [record(0, partition=1), record(3, b"junk")])
        for p in a.due(force=True):
            a.flush(p)
        assert main(["setup"]) == 0
        assert main(["restore", "--topic", "audit.v1"]) == 0
        assert '"events": 4, "rejects": 1, "duplicates": 0' in capsys.readouterr().out
        assert main(["restore", "--topic", "audit.v1"]) == 0  # again: nothing new
        assert '"events": 0, "rejects": 0, "duplicates": 5' in capsys.readouterr().out
        assert main(["verify"]) == 0
        db.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_change")
        db.execute("UPDATE audit_events SET action = 'x' WHERE \"offset\" = 0 AND partition = 0")
        db.execute(
            "UPDATE audit_events SET event = jsonb_set(event, '{data,action}', '\"x\"')"
            ' WHERE "offset" = 0 AND partition = 0'
        )
        assert main(["verify"]) == 1


def test_configuration_is_checked() -> None:
    with pytest.raises(RuntimeError, match="KAFKA_BOOTSTRAP"):
        app_mod.build_workers(Settings(kafka_bootstrap=""))
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        app_mod.connect(Settings())
    with pytest.raises(RuntimeError, match="ARCHIVE_BUCKET"):
        app_mod.archive_sink(Settings())
    with pytest.raises(RuntimeError, match="Unknown destination"):
        app_mod.build_workers(Settings(kafka_bootstrap="127.0.0.1:9", destinations=["syslog"]))


def test_workers_get_one_consumer_group_per_destination(db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    env(monkeypatch, db)
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="emr-audit")
        workers = app_mod.build_workers(Settings(kafka_bootstrap="127.0.0.1:9", poll_batch=7))
        assert [w.destination.name for w in workers] == ["postgres", "archive"]
        assert all(w.poll_batch == 7 for w in workers)
        for w in workers:
            w.consumer.close()


def test_old_and_new_event_types_are_both_audit_events() -> None:
    import json

    from .conftest import event

    for kind in ("valxel.audit.v1", "vrixel.audit.v1"):
        assert record(0, json.dumps({**event(), "type": kind}).encode()).event()["type"] == kind
    with pytest.raises(ValueError, match=r"not a valxel\.audit\.v1 event"):
        record(0, json.dumps({**event(), "type": "other.v1"}).encode()).event()


class FakeProducer:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[bytes] = []
        self.fail, self.pending = fail, []

    def produce(self, topic: str, value: bytes, on_delivery: Any) -> None:
        self.sent.append(value)
        self.pending.append(on_delivery)

    def flush(self, timeout: float) -> int:
        for cb in self.pending:
            cb("broker down" if self.fail else None, None)
        self.pending = []
        return 0


def test_rejects_that_are_audit_events_are_replayed_once(
    db: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """Events refused before the sink knew valxel.audit.v1 go back on the topic, never into the chain
    at their old offsets (that would fork it)."""
    import json

    from audit_sink import postgres
    from audit_sink.cli import replay_rejects

    from .conftest import event

    env(monkeypatch, db)
    assert main(["setup"]) == 0
    sink = postgres.PostgresSink(db)
    # As the old sink saw them: a valxel event refused for its type, and real junk.
    for offset, raw, reason in (
        (5, json.dumps({**event(), "type": "valxel.audit.v1"}).encode(), "not a vrixel.audit.v1 event"),
        (6, b"junk", "not JSON: x"),
    ):
        db.execute(
            'INSERT INTO audit_rejects (topic, partition, "offset", reason, raw) VALUES (%s, 0, %s, %s, %s)',
            ("audit.v1", offset, reason, raw),
        )
    sink.write([record(i) for i in range(3)])
    assert main(["replay-rejects", "--topic", "audit.v1", "--dry-run"]) == 0
    assert '"replayable": 1, "replayed": 0' in capsys.readouterr().out
    down = FakeProducer(fail=True)
    assert replay_rejects(db, Settings(), "audit.v1", dry_run=False, producer=down) == 1
    assert len(postgres.replayable(db, "audit.v1")) == 1  # not marked: it'll go next time
    up = FakeProducer()
    assert replay_rejects(db, Settings(), "audit.v1", dry_run=False, producer=up) == 0
    assert json.loads(up.sent[0])["type"] == "valxel.audit.v1"
    assert postgres.replayable(db, "audit.v1") == []
    # When the sink reads it back at its new offset, it joins the chain.
    sink.write([record(9, up.sent[0])])
    assert main(["verify"]) == 0


def test_setup_grants_the_writer_role_and_the_writer_skips_setup(
    db: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    env(monkeypatch, db)
    role = f"w_{db.info.dbname[-6:]}"
    try:
        monkeypatch.setenv("AUDIT_SINK_WRITER_PASSWORD", "s3cret-writer")
        monkeypatch.setenv("AUDIT_SINK_SETUP", "false")  # setup still sets up: it's what it's for
        assert main(["setup", "--grant-to", role]) == 0
        assert f"{role} may add rows" in capsys.readouterr().out
        granted = db.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants"
            " WHERE grantee = %s AND table_name = 'audit_events' ORDER BY 1",
            (role,),
        ).fetchall()
        assert [g[0] for g in granted] == ["INSERT", "SELECT"]
        assert db.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (role,)).fetchone()[0]
        assert main(["setup", "--grant-to", role]) == 0  # again: the password is reset, nothing fails
        db.execute("DROP TRIGGER audit_events_no_truncate ON audit_events")
        app_mod.connect(Settings(database_url=url_of(db), setup=False)).close()
        assert (
            db.execute(
                "SELECT count(*) FROM pg_trigger WHERE tgname = 'audit_events_no_truncate'"
            ).fetchone()[0]
            == 0
        )  # not set up again by a writer
    finally:
        if db.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            db.execute(f"DROP OWNED BY {role}")
        db.execute(f"DROP ROLE IF EXISTS {role}")

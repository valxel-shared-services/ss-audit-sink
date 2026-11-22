"""audit-sink run | setup | verify | restore --topic T | replay-rejects --topic T [--dry-run]

run       consume the audit topics into the configured destinations (the container's command)
setup     create the Postgres tables and append-only triggers
verify    recompute every partition's hash chain, and check it against its anchors; exits 1 on a break
anchor    write each partition's chain head under Object Lock (anchors.py); run it hourly
restore   replay a topic from the object-storage archive into Postgres (rows already there are
          skipped), e.g. after losing the database
replay-rejects
          publish again the rejects that are audit events after all (refused only for an event type
          the sink didn't know yet): they join the chain at new offsets; each is marked replayed
          once the broker acknowledges it, so running it twice sends nothing twice
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import postgres
from .settings import Settings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="audit-sink")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sp = sub.add_parser("setup")
    sp.add_argument("--grant-to", default="", help="a writer role that may only add audit rows")
    sub.add_parser("verify")
    sub.add_parser("anchor")
    r = sub.add_parser("restore")
    r.add_argument("--topic", required=True)
    rp = sub.add_parser("replay-rejects")
    rp.add_argument("--topic", required=True)
    rp.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='{"log.level":"%(levelname)s","message":"%(message)s"}')
    settings = Settings()
    from .app import anchors_for, archive_sink, build_workers, connect, create_app

    if args.cmd == "run":  # pragma: no cover - exercised by the container
        import threading

        import uvicorn

        from . import anchors

        workers = build_workers(settings)
        verify_conn = connect(settings) if "postgres" in settings.destinations else None
        store = anchors_for(settings) if verify_conn is not None else None
        if store is not None and settings.anchor_interval_s > 0:
            threading.Thread(
                target=anchors.loop,
                args=(threading.Event(), lambda: connect(settings), store, settings.anchor_interval_s),
                daemon=True,
                name="anchors",
            ).start()
        uvicorn.run(
            create_app(workers, verify_conn=verify_conn),
            host="0.0.0.0",  # noqa: S104 - a container listens on all interfaces
            port=settings.port,
            log_config=None,
        )
        return 0
    conn = connect(settings.model_copy(update={"setup": True}) if args.cmd == "setup" else settings)
    if args.cmd == "setup":
        if args.grant_to:
            postgres.grant(conn, args.grant_to, settings.writer_password)
        print("audit tables ready" + (f"; {args.grant_to} may add rows" if args.grant_to else ""))
        return 0
    if args.cmd == "anchor":
        from .anchors import anchor_all

        store = anchors_for(settings)
        if store is None:
            print("no archive bucket (AUDIT_SINK_ARCHIVE_BUCKET): nowhere to anchor")
            return 1
        print(f"anchored {anchor_all(conn, store)} partition heads")
        return 0
    if args.cmd == "verify":
        from .anchors import check

        ok = True
        store = anchors_for(settings)
        for topic, partition in postgres.partitions(conn):
            n, broken = postgres.verify(conn, topic, partition)
            against = list(check(conn, store, topic, partition)) if store is not None else None
            ok = ok and broken is None and not against
            print(
                json.dumps(
                    {
                        "topic": topic,
                        "partition": partition,
                        "checked": n,
                        "break": broken.__dict__ if broken else None,
                        "anchors": "not configured" if against is None else (against or "consistent"),
                    }
                )
            )
        return 0 if ok else 1
    if args.cmd == "replay-rejects":
        return replay_rejects(conn, settings, args.topic, dry_run=args.dry_run)
    from .archive import read

    arch = archive_sink(settings)
    sink = postgres.PostgresSink(conn)
    total = postgres.Written()
    batch: list = []  # type: ignore[type-arg]
    for rec in read(arch.s3, arch.bucket, arch.prefix, args.topic):
        batch.append(rec)
        if len(batch) >= 1000:
            _add(total, sink.write(batch))
            batch = []
    if batch:
        _add(total, sink.write(batch))
    print(json.dumps(total.__dict__))
    return 0


def replay_rejects(conn, settings: Settings, topic: str, *, dry_run: bool, producer=None) -> int:  # type: ignore[no-untyped-def]
    found = postgres.replayable(conn, topic)
    if dry_run or not found:
        print(json.dumps({"topic": topic, "replayable": len(found), "replayed": 0}))
        return 0
    if producer is None:  # pragma: no cover - a real broker
        from confluent_kafka import Producer

        if not settings.kafka_bootstrap:
            raise RuntimeError("Set AUDIT_SINK_KAFKA_BOOTSTRAP to replay rejects")
        producer = Producer(
            {
                "bootstrap.servers": settings.kafka_bootstrap,
                **settings.kafka_config,
                "acks": "all",
                "enable.idempotence": True,
            }
        )
    done: list[tuple[int, int]] = []
    failed: list[str] = []
    for partition, offset, raw in found:

        def ack(err, _msg, at=(partition, offset)) -> None:  # type: ignore[no-untyped-def]
            (failed if err else done).append(str(err) if err else at)  # type: ignore[arg-type]

        producer.produce(topic, value=raw, on_delivery=ack)
    producer.flush(60)
    postgres.mark_replayed(conn, topic, done)
    print(
        json.dumps({"topic": topic, "replayable": len(found), "replayed": len(done), "failed": len(failed)})
    )
    return 1 if failed or len(done) < len(found) else 0


def _add(total: postgres.Written, w: postgres.Written) -> None:
    total.events += w.events
    total.rejects += w.rejects
    total.duplicates += w.duplicates


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

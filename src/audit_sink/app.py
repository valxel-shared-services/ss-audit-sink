"""The service: one worker per destination, plus health, metrics and chain verification.

GET /healthz   liveness
GET /readyz    every worker is looping and none is stuck failing
GET /metrics   Prometheus: records written, rejected, duplicates; failures; last success
GET /verify    recompute the hash chain of every partition in Postgres
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from . import postgres
from .settings import Settings
from .worker import Worker

log = logging.getLogger("audit_sink")


def build_workers(settings: Settings) -> list[Worker]:
    if not settings.kafka_bootstrap:
        raise RuntimeError("Set AUDIT_SINK_KAFKA_BOOTSTRAP")
    from .worker import ArchiveDestination, ForwardDestination, PostgresDestination, kafka_consumer

    workers: list[Worker] = []
    for dest in settings.destinations:
        if dest == "postgres":
            workers.append(Worker(None, PostgresDestination(postgres.PostgresSink(connect(settings)))))
        elif dest == "archive":
            workers.append(Worker(None, ArchiveDestination(archive_sink(settings))))
        elif dest == "forward":
            workers.append(Worker(None, ForwardDestination(forward_sink(settings))))
        else:
            raise RuntimeError(f"Unknown destination {dest!r}: use postgres, archive or forward")
        w = workers[-1]
        w.consumer = kafka_consumer(
            settings.kafka_bootstrap,
            f"{settings.group_prefix}-{dest}",
            settings.topics,
            dict(settings.kafka_config),
            w,
        )
        w.poll_batch = settings.poll_batch
    return workers


def connect(settings: Settings) -> Any:
    import psycopg

    if not settings.database_url:
        raise RuntimeError("Set AUDIT_SINK_DATABASE_URL")
    conn = psycopg.connect(settings.database_url, autocommit=True)
    if settings.setup:
        postgres.setup(conn)
    return conn


def s3_client(settings: Settings) -> Any:
    """The archive's store, as an S3 client: S3 itself, or Cloud Storage behind the same calls."""
    if settings.archive_provider == "gcs":
        from .gcs import GcsAsS3

        return GcsAsS3()
    if settings.archive_provider != "s3":
        raise RuntimeError(f"AUDIT_SINK_ARCHIVE_PROVIDER is s3 or gcs, not {settings.archive_provider!r}")
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=settings.archive_endpoint_url or None,
        region_name=settings.archive_region or None,
    )


def anchors_for(settings: Settings, s3: Any = None) -> Any:
    """The chain heads' store (anchors.py): the archive bucket, under its own prefix. None without one."""
    from .anchors import Anchors

    if not settings.archive_bucket:
        return None
    return Anchors(
        s3 if s3 is not None else s3_client(settings),
        settings.archive_bucket,
        prefix=settings.anchor_prefix,
        lock_mode=settings.archive_lock_mode,
        retention_days=settings.archive_retention_days,
    )


def archive_sink(settings: Settings) -> Any:
    from .archive import ArchiveSink

    if not settings.archive_bucket:
        raise RuntimeError("Set AUDIT_SINK_ARCHIVE_BUCKET")
    s3 = s3_client(settings)
    return ArchiveSink(
        s3,
        settings.archive_bucket,
        prefix=settings.archive_prefix,
        lock_mode=settings.archive_lock_mode,
        retention_days=settings.archive_retention_days,
        batch_events=settings.archive_batch_events,
        batch_seconds=settings.archive_batch_seconds,
    )


def forward_sink(settings: Settings) -> Any:
    from .forward import ForwardSink

    if not settings.forward_url:
        raise RuntimeError("Set AUDIT_SINK_FORWARD_URL")
    return ForwardSink(
        settings.forward_kind,
        settings.forward_url,
        settings.forward_token,
        auth_header=settings.forward_auth_header,
        signing_key=settings.forward_signing_key,
        workspaces=settings.forward_workspaces,
        unscoped=settings.forward_unscoped,
        batch=settings.forward_batch,
    )


def create_app(workers: list[Worker], *, verify_conn: Any = None, stale_after: float = 120.0) -> FastAPI:
    stop = threading.Event()
    threads: list[threading.Thread] = []

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        for w in workers:
            t = threading.Thread(target=w.run, args=(stop,), name=f"sink-{w.destination.name}", daemon=True)
            t.start()
            threads.append(t)
        yield
        stop.set()
        for t in threads:
            t.join(30)

    app = FastAPI(title="Valxel audit sink", lifespan=lifespan, docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> Response:
        now = time.monotonic()
        state = {
            w.destination.name: {
                "alive": all(t.is_alive() for t in threads if t.name == f"sink-{w.destination.name}"),
                "looping": now - w.last_loop < stale_after,
                "failing": w.error,
            }
            for w in workers
        }
        ok = all(s["alive"] and s["looping"] and not s["failing"] for s in state.values())
        return JSONResponse(
            {"status": "ready" if ok else "not ready", "workers": state}, status_code=200 if ok else 503
        )

    @app.get("/metrics")
    def metrics() -> Response:
        return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/verify")
    def verify() -> Response:
        if verify_conn is None:
            return JSONResponse({"error": "this process doesn't write to Postgres"}, status_code=404)
        results, ok = [], True
        for topic, partition in postgres.partitions(verify_conn):
            n, broken = postgres.verify(verify_conn, topic, partition)
            ok = ok and broken is None
            results.append(
                {
                    "topic": topic,
                    "partition": partition,
                    "checked": n,
                    "break": broken.__dict__ if broken else None,
                }
            )
        return JSONResponse({"intact": ok, "partitions": results}, status_code=200 if ok else 409)

    return app

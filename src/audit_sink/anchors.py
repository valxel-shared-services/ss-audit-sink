"""Anchors: each partition's chain head, kept under Object Lock where the database can't reach it.

The Postgres copy is a hash chain, and the writer role can't turn its triggers off. But the tables'
owner can, and then rewrite rows and recompute every later hash, or delete the newest rows: the
chain still verifies. So the sink writes each partition's head (the last offset and its hash) to
the archive bucket under Object Lock, `anchors/<topic>/partition=<n>/<time>.json`, and `verify`
checks the chain against every anchor: an anchored row changed, or gone, is tampering however the
hashes were redone. Rows written since the last anchor have the chain's own protection only.

`audit-sink anchor` writes the heads once (run it hourly); `audit-sink run` does it every
AUDIT_SINK_ANCHOR_INTERVAL_S when it writes to Postgres and has an archive bucket.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from . import postgres

log = logging.getLogger("audit_sink")


def head(conn: psycopg.Connection[Any], topic: str, partition: int) -> dict[str, Any] | None:
    row = conn.execute(
        'SELECT "offset", hash FROM audit_events WHERE topic = %s AND partition = %s'
        ' ORDER BY "offset" DESC LIMIT 1',
        (topic, partition),
    ).fetchone()
    return (
        {"topic": topic, "partition": partition, "offset": int(row[0]), "hash": str(row[1])} if row else None
    )


class Anchors:
    def __init__(
        self,
        s3: Any,
        bucket: str,
        *,
        prefix: str = "anchors/",
        lock_mode: str = "COMPLIANCE",
        retention_days: int = 2190,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.s3, self.bucket, self.prefix = s3, bucket, prefix
        self.lock_mode, self.retention_days, self.now = lock_mode, retention_days, now

    def _dir(self, topic: str, partition: int) -> str:
        if not topic or "/" in topic or topic.startswith("."):
            raise ValueError(f"not a topic name: {topic!r}")
        return f"{self.prefix}{topic}/partition={int(partition)}/"

    def put(self, h: dict[str, Any]) -> str:
        at = self.now()
        key = f"{self._dir(h['topic'], h['partition'])}{at.strftime('%Y%m%dT%H%M%S%fZ')}.json"
        extra: dict[str, Any] = {}
        if self.lock_mode:
            extra = {
                "ObjectLockMode": self.lock_mode,
                "ObjectLockRetainUntilDate": at + timedelta(days=self.retention_days),
            }
        body = json.dumps({**h, "at": at.isoformat()}, sort_keys=True).encode()
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            **extra,
        )
        return key

    def _keys(self, topic: str, partition: int) -> list[str]:
        keys: list[str] = []
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": self.bucket, "Prefix": self._dir(topic, partition)}
            if token:
                kw["ContinuationToken"] = token
            page = self.s3.list_objects_v2(**kw)
            keys += [o["Key"] for o in page.get("Contents") or []]
            if not page.get("IsTruncated"):
                return sorted(keys)
            token = page.get("NextContinuationToken")

    def list(self, topic: str, partition: int, limit: int = 0) -> list[dict[str, Any]]:
        keys = self._keys(topic, partition)
        keys = keys[-limit:] if limit else keys
        return [json.loads(self.s3.get_object(Bucket=self.bucket, Key=k)["Body"].read()) for k in keys]


def anchor_all(conn: psycopg.Connection[Any], anchors: Anchors) -> int:
    """Write each partition's head when it moved since its last anchor. How many were written."""
    n = 0
    for topic, partition in postgres.partitions(conn):
        h = head(conn, topic, partition)
        if h is None:
            continue
        last = anchors.list(topic, partition, limit=1)
        if last and last[0]["offset"] == h["offset"] and last[0]["hash"] == h["hash"]:
            continue
        anchors.put(h)
        n += 1
    return n


def check(conn: psycopg.Connection[Any], anchors: Anchors, topic: str, partition: int) -> Iterator[str]:
    """What the partition contradicts: each anchored row must still be there with its anchored hash."""
    for a in anchors.list(topic, partition):
        row = conn.execute(
            'SELECT hash FROM audit_events WHERE topic = %s AND partition = %s AND "offset" = %s',
            (topic, partition, a["offset"]),
        ).fetchone()
        if row is None:
            yield f"offset {a['offset']}, anchored at {a.get('at', '?')}, is gone"
        elif str(row[0]) != a["hash"]:
            yield f"offset {a['offset']} no longer has the hash anchored at {a.get('at', '?')}: rewritten"


def loop(
    stop: threading.Event,
    conn_factory: Callable[[], psycopg.Connection[Any]],
    anchors: Anchors,
    interval_s: float,
) -> None:
    """Anchor every interval until stopped; a failed round is logged and tried again next time."""
    while not stop.wait(interval_s):
        try:
            with conn_factory() as conn:
                n = anchor_all(conn, anchors)
            log.info("anchored %d partition heads", n)
        except Exception:  # the next round tries again; the chain still has its own protection
            log.exception("anchoring failed")

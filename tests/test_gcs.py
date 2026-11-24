"""The archive on Cloud Storage (gcs.py, CP-111): the S3 calls the sink makes, on a fake of the
google-cloud-storage client: locked retention, written once, read back by `restore`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from audit_sink.app import s3_client
from audit_sink.archive import ArchiveSink, read
from audit_sink.gcs import GcsAsS3
from audit_sink.settings import Settings

from .conftest import record


class PreconditionFailed(Exception):
    code = 412


class FakeGcs:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}

    def bucket(self, name: str) -> Any:
        gcs = self

        class Blob:
            def __init__(self, key: str) -> None:
                self.name, self.metadata, self.content_encoding = key, None, None
                self.retention = SimpleNamespace(mode=None, retain_until_time=None)

            def upload_from_string(self, data: bytes, content_type: str, if_generation_match: int) -> None:
                assert if_generation_match == 0
                if (name, self.name) in gcs.objects:
                    raise PreconditionFailed(self.name)
                gcs.objects[(name, self.name)] = {
                    "data": data,
                    "type": content_type,
                    "meta": self.metadata,
                    "encoding": self.content_encoding,
                    "mode": self.retention.mode,
                    "until": self.retention.retain_until_time,
                }

            def download_as_bytes(self) -> bytes:
                return bytes(gcs.objects[(name, self.name)]["data"])

        return SimpleNamespace(blob=Blob)

    def list_blobs(self, bucket: str, prefix: str = "") -> list[Any]:
        return [SimpleNamespace(name=k) for b, k in self.objects if b == bucket and k.startswith(prefix)]


def test_the_archive_writes_locked_objects_and_restore_reads_them() -> None:
    gcs = FakeGcs()
    when = datetime(2026, 11, 23, tzinfo=UTC)
    a = ArchiveSink(GcsAsS3(gcs), "acme-audit", batch_events=2, now=lambda: when, retention_days=2190)
    a.add([record(0), record(1)])
    key, last = a.flush(("audit.v1", 0))
    obj = gcs.objects[("acme-audit", key)]
    assert (obj["mode"], obj["until"], obj["encoding"]) == ("Locked", when + timedelta(days=2190), "gzip")
    assert obj["meta"]["records"] == "2" and last == 1
    assert [r.offset for r in read(GcsAsS3(gcs), "acme-audit", "audit/", "audit.v1")] == [0, 1]


def test_a_file_written_again_after_a_rebalance_keeps_the_first_copy() -> None:
    gcs = FakeGcs()
    for _ in range(2):
        a = ArchiveSink(GcsAsS3(gcs), "acme-audit", batch_events=1)
        a.add([record(5)])
        a.flush(("audit.v1", 0))
    assert len(gcs.objects) == 1


def test_governance_mode_is_unlocked_retention_and_bad_modes_are_refused() -> None:
    gcs, until = FakeGcs(), datetime(2030, 1, 1, tzinfo=UTC)
    GcsAsS3(gcs).put_object(
        Bucket="b", Key="k", Body=b"x", ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=until
    )
    assert gcs.objects[("b", "k")]["mode"] == "Unlocked"
    with pytest.raises(ValueError, match="COMPLIANCE or GOVERNANCE"):
        GcsAsS3(gcs).put_object(
            Bucket="b", Key="k2", Body=b"x", ObjectLockMode="LEGAL_HOLD", ObjectLockRetainUntilDate=until
        )


def test_the_provider_setting_picks_the_store(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_sink.gcs as gcs_mod

    monkeypatch.setattr(
        gcs_mod.GcsAsS3, "__init__", lambda self, client=None: setattr(self, "client", "fake")
    )
    assert isinstance(s3_client(Settings(archive_provider="gcs")), GcsAsS3)
    with pytest.raises(RuntimeError, match="s3, gcs or azure"):
        s3_client(Settings(archive_provider="oracle"))

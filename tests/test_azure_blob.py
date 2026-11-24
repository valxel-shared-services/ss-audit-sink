"""The archive on Azure Blob Storage (azure_blob.py, CP-410): the S3 calls the sink makes, on a fake
of the azure-storage-blob container client: locked per-blob immutability, written once, read back
by `restore`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from audit_sink.app import s3_client
from audit_sink.archive import ArchiveSink, read
from audit_sink.azure_blob import AzureBlobAsS3
from audit_sink.settings import Settings

from .conftest import record

URL = "https://acmevalxel.blob.core.windows.net/audit"


class ResourceExistsError(Exception):
    status_code = 409


class FakeContainer:
    def __init__(self) -> None:
        self.blobs: dict[str, dict[str, Any]] = {}

    def upload_blob(
        self,
        name: str,
        data: bytes,
        *,
        overwrite: bool,
        content_settings: Any,
        metadata: Any,
        immutability_policy: Any,
    ) -> None:
        assert overwrite is False
        if name in self.blobs:
            raise ResourceExistsError(name)
        self.blobs[name] = {
            "data": data,
            "settings": content_settings,
            "meta": metadata,
            "policy": immutability_policy,
        }

    def list_blobs(self, name_starts_with: str | None = None) -> list[Any]:
        return [SimpleNamespace(name=k) for k in self.blobs if k.startswith(name_starts_with or "")]

    def download_blob(self, name: str) -> Any:
        return SimpleNamespace(readall=lambda: self.blobs[name]["data"])


def store(box: FakeContainer) -> AzureBlobAsS3:
    def containers(url: str) -> FakeContainer:
        assert url == URL
        return box

    return AzureBlobAsS3(containers)


def test_the_archive_writes_locked_blobs_and_restore_reads_them() -> None:
    box = FakeContainer()
    when = datetime(2026, 11, 24, tzinfo=UTC)
    a = ArchiveSink(store(box), URL + "/", batch_events=2, now=lambda: when, retention_days=2190)
    a.add([record(0), record(1)])
    key, last = a.flush(("audit.v1", 0))
    blob = box.blobs[key]
    assert (blob["policy"].policy_mode, blob["policy"].expiry_time) == ("Locked", when + timedelta(days=2190))
    assert blob["settings"].content_encoding == "gzip" and blob["meta"]["records"] == "2" and last == 1
    assert [r.offset for r in read(store(box), URL, "audit/", "audit.v1")] == [0, 1]


def test_a_blob_written_again_after_a_rebalance_keeps_the_first_copy() -> None:
    box = FakeContainer()
    for _ in range(2):
        a = ArchiveSink(store(box), URL, batch_events=1)
        a.add([record(5)])
        a.flush(("audit.v1", 0))
    assert len(box.blobs) == 1


def test_governance_is_unlocked_bad_modes_and_buckets_are_refused() -> None:
    box, until = FakeContainer(), datetime(2030, 1, 1, tzinfo=UTC)
    store(box).put_object(
        Bucket=URL,
        Key="k",
        Body=b"x",
        ObjectLockMode="GOVERNANCE",
        ObjectLockRetainUntilDate=until,
        Metadata={"x-sha": "a", "1st": "b"},
    )
    assert box.blobs["k"]["policy"].policy_mode == "Unlocked"
    assert box.blobs["k"]["meta"] == {"x_sha": "a", "m_1st": "b"}
    with pytest.raises(ValueError, match="COMPLIANCE or GOVERNANCE"):
        store(box).put_object(
            Bucket=URL, Key="k2", Body=b"x", ObjectLockMode="LEGAL_HOLD", ObjectLockRetainUntilDate=until
        )
    with pytest.raises(ValueError, match="container's URL"):
        store(box).put_object(Bucket="audit", Key="k3", Body=b"x")


def test_the_provider_setting_picks_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_sink.azure_blob as az

    monkeypatch.setattr(az.AzureBlobAsS3, "__init__", lambda self, containers=None: None)
    assert isinstance(s3_client(Settings(archive_provider="azure")), AzureBlobAsS3)

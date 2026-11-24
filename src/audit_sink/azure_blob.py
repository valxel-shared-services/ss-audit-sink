"""Azure Blob Storage for the archive and the anchors, through the subset of the S3 client they use
(agentic-sdlc ADR 0010; tracker CP-410): `put_object`, `list_objects_v2` and `get_object`.

AUDIT_SINK_ARCHIVE_PROVIDER=azure, and AUDIT_SINK_ARCHIVE_BUCKET is the container's URL,
https://<account>.blob.core.windows.net/<container>. The container has version-level
immutability support, and each blob is written with its own time-based retention policy: Object
Lock's COMPLIANCE is Azure's Locked mode (no one can shorten it or delete the blob until it ends,
the subscription owner included) and GOVERNANCE its Unlocked mode. Blobs are written once
(`overwrite=False`): a file the sink writes again after a rebalance holds the same offsets, so the
copy already there is kept. Credentials are the pod's own (AKS Workload Identity, through
DefaultAzureCredential); the storage account's customer-managed key encrypts it.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from types import SimpleNamespace
from typing import Any

log = logging.getLogger(__name__)
MODES = {"COMPLIANCE": "Locked", "GOVERNANCE": "Unlocked"}


def _exists(exc: Exception) -> bool:
    return type(exc).__name__ == "ResourceExistsError" or getattr(exc, "status_code", None) in (409, 412)


def _meta_key(k: str) -> str:
    """Blob metadata names are C# identifiers: letters, digits and `_`, not starting with a digit."""
    out = "".join(c if c.isalnum() or c == "_" else "_" for c in k)
    return out if out[:1].isalpha() else f"m_{out}"


def _types() -> tuple[Any, Any]:
    try:
        from azure.storage.blob import ContentSettings, ImmutabilityPolicy
    except ImportError:  # a fake client in tests; the real client needs the SDK anyway
        return SimpleNamespace, SimpleNamespace
    return ContentSettings, ImmutabilityPolicy


class AzureBlobAsS3:
    """`Bucket` is the container's URL; `containers(url)` gives its ContainerClient."""

    def __init__(self, containers: Any = None) -> None:
        if containers is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import ContainerClient

            credential = DefaultAzureCredential()
            containers = lambda url: ContainerClient.from_container_url(url, credential=credential)  # noqa: E731
        self._containers = containers
        self._open: dict[str, Any] = {}

    def _container(self, bucket: str) -> Any:
        url = bucket.rstrip("/")
        if not url.startswith("https://") or "/" not in url[len("https://") :]:
            raise ValueError(
                f"On Azure the bucket is the container's URL, https://<account>.blob.core.windows.net/"
                f"<container>, not {bucket!r}"
            )
        if url not in self._open:
            self._open[url] = self._containers(url)
        return self._open[url]

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str = "application/octet-stream",
        ContentEncoding: str = "",
        Metadata: dict[str, str] | None = None,
        ObjectLockMode: str = "",
        ObjectLockRetainUntilDate: datetime | None = None,
        **_: Any,  # ChecksumAlgorithm: Blob Storage checks every upload with its own MD5/CRC64
    ) -> dict[str, Any]:
        settings_cls, policy_cls = _types()
        policy = None
        if ObjectLockMode:
            if ObjectLockMode not in MODES or ObjectLockRetainUntilDate is None:
                raise ValueError(f"lock mode {ObjectLockMode!r} needs COMPLIANCE or GOVERNANCE and a date")
            policy = policy_cls(expiry_time=ObjectLockRetainUntilDate, policy_mode=MODES[ObjectLockMode])
        try:
            self._container(Bucket).upload_blob(
                Key,
                Body,
                overwrite=False,
                content_settings=settings_cls(
                    content_type=ContentType, content_encoding=ContentEncoding or None
                ),
                metadata={_meta_key(k): v for k, v in (Metadata or {}).items()} or None,
                immutability_policy=policy,
            )
        except Exception as exc:
            if not _exists(exc):
                raise
            log.info("%s/%s is already written; keeping it", Bucket.rstrip("/"), Key)
        return {}

    def list_objects_v2(self, *, Bucket: str, Prefix: str = "", **_: Any) -> dict[str, Any]:
        keys = sorted(b.name for b in self._container(Bucket).list_blobs(name_starts_with=Prefix or None))
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        return {"Body": io.BytesIO(bytes(self._container(Bucket).download_blob(Key).readall()))}

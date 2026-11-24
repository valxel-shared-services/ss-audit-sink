"""Cloud Storage for the archive and the anchors, through the subset of the S3 client they use
(agentic-sdlc ADR 0010; tracker CP-111): `put_object`, `list_objects_v2` and `get_object`.

AUDIT_SINK_ARCHIVE_PROVIDER=gcs. The bucket has per-object retention enabled, and each object is
written with its own retention: Object Lock's COMPLIANCE is Cloud Storage's Locked mode (no one
can shorten it or delete the object until it ends) and GOVERNANCE its Unlocked mode. Objects are
written once (`if_generation_match=0`): a file the sink writes again after a rebalance holds the
same offsets, so the copy already there is kept. Credentials are the pod's own (GKE Workload
Identity); the bucket's default key (CMEK) encrypts it.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)
MODES = {"COMPLIANCE": "Locked", "GOVERNANCE": "Unlocked"}


def _code(exc: Exception) -> int | None:
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else None


class GcsAsS3:
    def __init__(self, client: Any = None) -> None:
        if client is None:
            from google.cloud import storage

            client = storage.Client()
        self.client = client

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
        **_: Any,  # ChecksumAlgorithm: Cloud Storage checks every upload with CRC32C itself
    ) -> dict[str, Any]:
        blob = self.client.bucket(Bucket).blob(Key)
        blob.metadata = dict(Metadata) if Metadata else None
        if ContentEncoding:
            blob.content_encoding = ContentEncoding
        if ObjectLockMode:
            if ObjectLockMode not in MODES or ObjectLockRetainUntilDate is None:
                raise ValueError(f"lock mode {ObjectLockMode!r} needs COMPLIANCE or GOVERNANCE and a date")
            blob.retention.mode = MODES[ObjectLockMode]
            blob.retention.retain_until_time = ObjectLockRetainUntilDate
        try:
            blob.upload_from_string(Body, content_type=ContentType, if_generation_match=0)
        except Exception as exc:
            if _code(exc) != 412 and type(exc).__name__ != "PreconditionFailed":
                raise
            log.info("gs://%s/%s is already written; keeping it", Bucket, Key)
        return {}

    def list_objects_v2(self, *, Bucket: str, Prefix: str = "", **_: Any) -> dict[str, Any]:
        keys = sorted(b.name for b in self.client.list_blobs(Bucket, prefix=Prefix))
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        return {"Body": io.BytesIO(self.client.bucket(Bucket).blob(Key).download_as_bytes())}

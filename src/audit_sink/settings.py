"""Configuration from the environment (AUDIT_SINK_*). Credentials come from OpenChoreo secret
references; nothing secret has a default."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUDIT_SINK_")

    # Kafka: the product's audit topics, read by one consumer group per destination.
    kafka_bootstrap: str = ""
    kafka_config: dict[str, str] = Field(default_factory=dict)  # security.protocol, sasl.* ...
    topics: list[str] = Field(default_factory=lambda: ["audit.v1"])
    group_prefix: str = "audit-sink"
    # Which destinations this process writes: postgres, archive, forward (the customer's SIEM).
    destinations: list[str] = Field(default_factory=lambda: ["postgres", "archive"])
    # Postgres: the queryable, hash-chained copy.
    database_url: str = ""
    # The product's own audit contract (its governance repo's contracts/audit/ schema, mounted here);
    # empty: the platform's default. Read when the sink starts (records.schema()).
    schema_file: str = ""
    # Create the tables and triggers on start. Turn off when the sink runs as a writer role that
    # may only add rows (`audit-sink setup --grant-to <role>`, run as the tables' owner).
    setup: bool = True
    # With `setup --grant-to`: the writer's login password, so the owner creates (or resets) the role.
    writer_password: str = ""
    # Object storage: the backup. s3 (the S3 API: AWS S3, MinIO, Ceph), gcs (Cloud Storage with
    # per-object retention, gcs.py) or azure (Blob Storage with version-level immutability,
    # azure_blob.py; the bucket is the container's URL), matching the installation's cloud.
    archive_provider: str = "s3"
    archive_bucket: str = ""
    archive_prefix: str = "audit/"
    archive_endpoint_url: str = ""  # MinIO or another S3-compatible store; empty for AWS
    archive_region: str = ""
    archive_lock_mode: str = "COMPLIANCE"  # COMPLIANCE | GOVERNANCE | "" (bucket default)
    archive_retention_days: int = 2190  # six years, the HIPAA documentation period
    archive_batch_events: int = 5000  # write a file when a partition has this many records,
    archive_batch_seconds: int = 300  # or when its oldest unwritten record is this old
    # Anchors (anchors.py): each partition's chain head under Object Lock in the archive bucket,
    # every this many seconds while `run` writes to Postgres (0: only by `audit-sink anchor`).
    anchor_prefix: str = "anchors/"
    anchor_interval_s: int = 3600
    # The customer's SIEM (forward.py): splunk or webhook, its URL and token (a secret reference).
    forward_kind: str = "webhook"
    forward_url: str = ""
    forward_token: str = ""
    forward_auth_header: str = ""  # default Authorization: Bearer <token>; DD-API-KEY for Datadog
    forward_signing_key: str = ""  # HMAC-SHA256 of each body, X-Valxel-Signature
    forward_workspaces: list[str] = Field(default_factory=list)  # only these workspaces' records
    forward_unscoped: bool = False  # with forward_workspaces: also records naming no workspace
    forward_batch: int = 500
    poll_batch: int = 500
    port: int = 8080

"""The third destination: the customer's own security monitoring (their SIEM).

A customer's security team keeps every system's logs in one place (Splunk, Microsoft Sentinel,
Datadog, Elastic...) to watch for threats and to keep as evidence. This destination sends each
audit record there as it arrives, from a consumer group of its own, so a SIEM that is down or slow
never holds up Postgres or the archive: Kafka keeps the records until it is back, and nothing is
committed until the SIEM has accepted them. Delivery is at least once; each event's `id` lets the
SIEM drop a repeat.

Two ways in:

    splunk    Splunk's HTTP Event Collector: POST <url>/services/collector/event, one JSON object
              per record ({"time", "sourcetype": "valxel:audit", "event"}), header
              `Authorization: Splunk <token>`
    webhook   any HTTPS endpoint that takes a JSON array of events: Sentinel through a Logic App or
              Azure Function, Datadog's log intake, Elastic, a customer's own collector. The token
              goes in AUDIT_SINK_FORWARD_AUTH_HEADER (Authorization: Bearer <token> by default;
              DD-API-KEY for Datadog). With AUDIT_SINK_FORWARD_SIGNING_KEY each body is signed:
              X-Valxel-Signature: sha256=<HMAC of the body>.

AUDIT_SINK_FORWARD_WORKSPACES limits what is sent to some workspaces' records (the tool's own
sink serves many customers; a product's sink is one customer's). Records naming no workspace go
too only with AUDIT_SINK_FORWARD_UNSCOPED. Only HTTPS is accepted, but for a test endpoint on
localhost.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .records import Record

log = logging.getLogger("audit_sink")

KINDS = ("splunk", "webhook")


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    req = Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - https only, checked in ForwardSink
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return int(resp.status)


class ForwardSink:
    def __init__(
        self,
        kind: str,
        url: str,
        token: str,
        *,
        auth_header: str = "",
        signing_key: str = "",
        workspaces: list[str] | None = None,
        unscoped: bool = False,
        batch: int = 500,
        timeout: float = 10.0,
        post: Callable[[str, bytes, dict[str, str], float], int] = _post,
    ) -> None:
        if kind not in KINDS:
            raise RuntimeError(f"AUDIT_SINK_FORWARD_KIND is {kind!r}: use one of {', '.join(KINDS)}")
        u = urlparse(url)
        if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1"):
            raise RuntimeError("AUDIT_SINK_FORWARD_URL must be https")
        if not token:
            raise RuntimeError("Set AUDIT_SINK_FORWARD_TOKEN: the SIEM's token for this sink")
        self.kind, self.url, self.token = kind, url.rstrip("/"), token
        self.auth_header = auth_header or "Authorization"
        self.signing_key = signing_key
        self.workspaces = set(workspaces or [])
        self.unscoped, self.batch, self.timeout, self.post = unscoped, batch, timeout, post

    def wanted(self, event: dict[str, Any]) -> bool:
        ws = ((event.get("data") or {}).get("details") or {}).get("workspace") or ""
        if not ws:
            return self.unscoped or not self.workspaces
        return not self.workspaces or ws in self.workspaces

    def events(self, records: list[Record]) -> tuple[list[dict[str, Any]], int]:
        """The records to send, and how many weren't audit events (the other sinks reject those too)."""
        out, bad = [], 0
        for r in records:
            try:
                e = r.event()
            except ValueError:
                bad += 1
                continue
            if self.wanted(e):
                out.append(e)
        return out, bad

    def send(self, events: list[dict[str, Any]]) -> None:
        """Every event, in batches; raises unless the SIEM accepted each batch (2xx)."""
        for i in range(0, len(events), self.batch):
            chunk = events[i : i + self.batch]
            if self.kind == "splunk":
                body = "\n".join(
                    json.dumps(
                        {
                            "time": datetime.fromisoformat(str(e["time"])).timestamp(),
                            "sourcetype": "valxel:audit",
                            "source": str(e.get("source") or "valxel"),
                            "event": e,
                        },
                        separators=(",", ":"),
                    )
                    for e in chunk
                ).encode()
                url, headers = (
                    f"{self.url}/services/collector/event",
                    {"Authorization": f"Splunk {self.token}"},
                )
            else:
                body = json.dumps(chunk, separators=(",", ":")).encode()
                value = f"Bearer {self.token}" if self.auth_header.lower() == "authorization" else self.token
                url, headers = self.url, {self.auth_header: value}
                if self.signing_key:
                    sig = hmac.new(self.signing_key.encode(), body, hashlib.sha256).hexdigest()
                    headers["X-Valxel-Signature"] = f"sha256={sig}"
            headers["Content-Type"] = "application/json"
            status = self.post(url, body, headers, self.timeout)
            if not 200 <= status < 300:
                raise RuntimeError(f"the SIEM answered {status}")

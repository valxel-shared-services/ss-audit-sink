"""The customer's SIEM as a third destination (forward.py)."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from audit_sink.app import forward_sink
from audit_sink.forward import ForwardSink
from audit_sink.settings import Settings
from audit_sink.worker import ForwardDestination, Worker

from .conftest import event, record


def posts() -> tuple[list[tuple[str, bytes, dict[str, str]]], Any]:
    got: list[tuple[str, bytes, dict[str, str]]] = []
    status = {"code": 200}

    def post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        got.append((url, body, headers))
        return status["code"]

    return got, (post, status)


def test_splunk_gets_one_event_object_per_record_with_its_token() -> None:
    got, (post, _) = posts()
    s = ForwardSink("splunk", "https://splunk.acme.example:8088/", "tok", post=post)
    s.send([event(), event("tool.update_patient")])
    [(url, body, headers)] = got
    assert url == "https://splunk.acme.example:8088/services/collector/event"
    assert headers["Authorization"] == "Splunk tok"
    lines = [json.loads(x) for x in body.decode().splitlines()]
    assert [x["event"]["data"]["action"] for x in lines] == ["tool.find_patient", "tool.update_patient"]
    assert lines[0]["sourcetype"] == "valxel:audit" and isinstance(lines[0]["time"], float)


def test_a_webhook_gets_json_arrays_signed_and_in_batches() -> None:
    got, (post, _) = posts()
    s = ForwardSink("webhook", "https://siem.acme.example/in", "tok", signing_key="k", batch=2, post=post)
    s.send([event(), event(), event()])
    assert [len(json.loads(b)) for _, b, _ in got] == [2, 1]
    _, body, headers = got[0]
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-Valxel-Signature"] == "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    dd, (post2, _) = posts()
    ForwardSink(
        "webhook",
        "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "key",
        auth_header="DD-API-KEY",
        post=post2,
    ).send([event()])
    assert dd[0][2]["DD-API-KEY"] == "key"


def test_only_the_customers_workspaces_go() -> None:
    s = ForwardSink("webhook", "https://siem.example/in", "t", workspaces=["acme"], post=lambda *a: 200)
    mine, theirs, none = (
        record(0, event(details={"workspace": "acme"})),
        record(1, event(details={"workspace": "beta"})),
        record(2, event()),
    )
    sent, bad = s.events([mine, theirs, none, record(3, b"not json")])
    assert [e["data"]["details"].get("workspace") for e in sent] == ["acme"] and bad == 1
    s.unscoped = True
    assert len(s.events([mine, theirs, none])[0]) == 2


def test_offsets_move_only_once_the_siem_took_everything() -> None:
    got, (post, status) = posts()
    dest = ForwardDestination(ForwardSink("webhook", "https://siem.example/in", "t", post=post))
    status["code"] = 503
    with pytest.raises(RuntimeError, match="503"):
        dest.handle([record(0), record(1)])
    status["code"] = 202
    assert dest.handle([record(2)]) == {("audit.v1", 0): 3}  # the two kept from the failure, then the new one
    assert len(json.loads(got[-1][1])) == 3


def test_a_failing_siem_is_retried_by_the_worker() -> None:
    _, (post, status) = posts()
    dest = ForwardDestination(ForwardSink("webhook", "https://siem.example/in", "t", post=post))

    class Consumer:
        def consume(self, num_messages: int, timeout: float) -> list[Any]:
            return []

    status["code"] = 500
    dest.buffer = [record(0)]
    w = Worker(Consumer(), dest, sleep=lambda s: None)
    w.step()
    assert w.failing and "500" in w.error


def test_settings_refuse_plain_http_and_a_missing_token() -> None:
    with pytest.raises(RuntimeError, match="https"):
        ForwardSink("webhook", "http://siem.example/in", "t")
    with pytest.raises(RuntimeError, match="TOKEN"):
        ForwardSink("webhook", "https://siem.example/in", "")
    with pytest.raises(RuntimeError, match="FORWARD_URL"):
        forward_sink(Settings(forward_url=""))
    with pytest.raises(RuntimeError, match="FORWARD_KIND"):
        ForwardSink("syslog", "https://siem.example/in", "t")


def test_a_real_endpoint_receives_the_records() -> None:
    seen: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            seen.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    s = ForwardSink("webhook", f"http://localhost:{server.server_port}/in", "t")
    s.send([event()])
    server.server_close()
    assert json.loads(seen[0])[0]["type"] == "valxel.audit.v1"

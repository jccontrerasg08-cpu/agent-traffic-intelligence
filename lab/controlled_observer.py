#!/usr/bin/env python3
"""Small local observation target for an authorized ATI shadow-mode campaign."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TextIO, cast
from urllib.parse import urlsplit


def build_observation_record(
    *,
    request_uri: str,
    headers: Mapping[str, str] | Message[str, str],
    status: int,
    bytes_sent: int,
    observed_at: datetime | None = None,
) -> dict[str, str | int | bool]:
    """Build a minimized access record for the owned controlled target."""

    lab_client = headers.get("X-ATI-Lab-Client", "browser")
    remote_addr = {
        "controlled": "198.51.100.10",
        "browser": "198.51.100.20",
    }.get(lab_client, "198.51.100.30")
    record: dict[str, str | int | bool] = {
        "time_iso8601": (observed_at or datetime.now(UTC)).isoformat(),
        "remote_addr": remote_addr,
        "request_method": "GET",
        "request_uri": urlsplit(request_uri).path or "/",
        "status": status,
        "body_bytes_sent": bytes_sent,
        "server_protocol": "HTTP/1.1",
        "http_user_agent": headers.get("User-Agent", ""),
        "has_referer": bool(headers.get("Referer")),
        "has_cookie": bool(headers.get("Cookie")),
        "has_accept_language": bool(headers.get("Accept-Language")),
    }
    campaign_id = headers.get("X-ATI-Experiment-ID")
    if campaign_id:
        record["ati_campaign_id"] = campaign_id
    return record


class ObservationHandler(BaseHTTPRequestHandler):
    server_version = "ATIControlledTarget/1.0"

    def do_GET(self) -> None:
        request_path = urlsplit(self.path).path or "/"
        status = 404 if request_path == "/missing" else 200
        body = (
            b"<!doctype html><html><body><h1>ATI controlled target</h1></body></html>"
            if request_path == "/"
            else b"ok"
        )
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        record = build_observation_record(
            request_uri=self.path,
            headers=self.headers,
            status=status,
            bytes_sent=len(body),
        )
        server = cast(ObservationServer, self.server)
        server.access_log.write(json.dumps(record, separators=(",", ":")) + "\n")
        server.access_log.flush()

    def log_message(self, _format: str, *_args: object) -> None:
        return


class ObservationServer(ThreadingHTTPServer):
    access_log: TextIO


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", encoding="utf-8") as access_log:
        server = ObservationServer((args.host, args.port), ObservationHandler)
        server.access_log = access_log
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

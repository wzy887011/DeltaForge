#!/usr/bin/env python3
"""Small self-hosted observation endpoint for DeltaForge network audits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path


def canonical_ip(value: str) -> str | None:
    candidate = value.strip().split(",", 1)[0].strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


class ProbeHandler(BaseHTTPRequestHandler):
    server_version = "DeltaForgeProbe/8.7"

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] not in {"/", "/v1/observe", "/healthz"}:
            self.send_error(404)
            return
        if self.path.startswith("/healthz"):
            self._json({"status": "ok"})
            return

        peer_ip, peer_port = self.client_address[:2]
        forwarded = self.headers.get("X-Forwarded-For", "")
        real_ip = self.headers.get("X-Real-IP", "")
        trust_proxy = self.server.trust_proxy  # type: ignore[attr-defined]
        observed = canonical_ip(peer_ip)
        if trust_proxy:
            observed = canonical_ip(forwarded) or canonical_ip(real_ip) or observed
        now = datetime.now(timezone.utc).isoformat()
        nonce = uuid.uuid4().hex
        payload = {
            "schema": 1,
            "timestamp": now,
            "request_id": nonce,
            "observed_ip": observed,
            "peer_ip": canonical_ip(peer_ip),
            "peer_port": peer_port,
            "forwarded_for_present": bool(forwarded),
            "real_ip_present": bool(real_ip),
            "proxy_headers_trusted": trust_proxy,
            "user_agent_sha256": hashlib.sha256(
                self.headers.get("User-Agent", "").encode("utf-8")
            ).hexdigest(),
            "transport": "https" if trust_proxy and self.headers.get("X-Forwarded-Proto") == "https" else "http",
            "asn": None,
            "network_type": "unknown",
            "note": "Populate ASN/network_type from your internal IP intelligence pipeline.",
        }
        self._append(payload)
        self._json(payload)

    def _append(self, payload: dict[str, object]) -> None:
        log_path = Path(self.server.log_path)  # type: ignore[attr-defined]
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            stream.write("\n")

    def _json(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        print("%s %s" % (self.log_date_time_string(), fmt % args), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default=os.environ.get("PROBE_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PROBE_PORT", "8787")))
    parser.add_argument("--log", default=os.environ.get("PROBE_LOG", "probe-events.jsonl"))
    parser.add_argument(
        "--trust-proxy",
        action="store_true",
        default=os.environ.get("PROBE_TRUST_PROXY", "0") == "1",
        help="trust forwarding headers from a controlled reverse proxy",
    )
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), ProbeHandler)
    server.log_path = args.log  # type: ignore[attr-defined]
    server.trust_proxy = args.trust_proxy  # type: ignore[attr-defined]
    print(f"listening=http://{args.bind}:{args.port} log={args.log}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

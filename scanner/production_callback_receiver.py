#!/usr/bin/env python3
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SECRET = os.environ.get("CALLBACK_SECRET", "")
OUTPUT = Path(os.environ.get("CALLBACK_OUTPUT", "/tmp/production-callback-results.jsonl"))

if not SECRET:
    raise SystemExit("Missing CALLBACK_SECRET")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return

        supplied = self.headers.get("x-helpdesk-scan-secret", "")
        if not hmac.compare_digest(supplied, SECRET):
            self.send_response(401)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 64 * 1024:
                raise ValueError("invalid body size")
            payload = json.loads(self.rfile.read(length))
            required = {"attachment_id", "previous_storage_key", "safe_storage_key", "scan_result", "scanner", "scanner_version", "scan_error", "sha256"}
            if not required.issubset(payload):
                raise ValueError("missing production callback fields")
            if payload["scan_result"] not in {"clean", "infected", "error"}:
                raise ValueError("invalid scan_result")
            if payload["scanner"] != "zero-clamav":
                raise ValueError("unexpected scanner")
            if payload["scan_result"] == "clean" and not payload["safe_storage_key"]:
                raise ValueError("clean callback must include safe_storage_key")
            if payload["scan_result"] != "clean" and payload["safe_storage_key"] is not None:
                raise ValueError("non-clean callback must not include safe_storage_key")
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            with OUTPUT.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
        except Exception as exc:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(exc).encode("utf-8"))
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return


HTTPServer(("0.0.0.0", 8787), Handler).serve_forever()

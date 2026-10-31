#!/usr/bin/env python3
"""Publish live overlay roster. Bind loopback + wg0 only — never 0.0.0.0."""
from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# deployed copy may live without the lib package
ROOT = Path(__file__).resolve().parent
for p in (ROOT.parent, Path("/usr/local/lib/riptide")):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from lib.roster import decorate, parse_wg_dump, wg_dump_cmd  # noqa: E402


def build(roster_path: Path, cache: Path) -> dict:
    roster = json.loads(roster_path.read_text(encoding="utf-8"))
    dump = parse_wg_dump(wg_dump_cmd())
    return decorate(roster, dump, cache_dir=cache)


def serve(host: str, port: int, roster_path: Path, cache: Path) -> None:
    class H(BaseHTTPRequestHandler):
        server_version = "RiptideRoster/1"

        def log_message(self, fmt: str, *a: object) -> None:
            print(f"[roster {host}] {self.address_string()} {fmt % a}")

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/api/hosts":
                self.send_error(404)
                return
            body = json.dumps(build(roster_path, cache)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    try:
        httpd = ThreadingHTTPServer((host, port), H)
    except OSError as e:
        print(f"[!] bind {host}:{port}: {e}")
        return
    print(f"[+] roster http://{host}:{port}/api/hosts")
    httpd.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roster", default="/etc/riptide/roster.json")
    ap.add_argument("--cache", default="/var/cache/riptide")
    ap.add_argument("--port", type=int, default=7668)
    ap.add_argument("--once", action="store_true", help="print JSON and exit")
    args = ap.parse_args()
    roster_path = Path(args.roster)
    cache = Path(args.cache)
    if args.once:
        print(json.dumps(build(roster_path, cache), indent=2))
        return
    binds = ["127.0.0.1"]
    try:
        doc = json.loads(roster_path.read_text(encoding="utf-8"))
        overlay = doc.get("hub", {}).get("overlay")
        if overlay:
            binds.append(overlay)
    except Exception:
        pass
    threads = []
    for h in binds:
        t = threading.Thread(target=serve, args=(h, args.port, roster_path, cache), daemon=True)
        t.start()
        threads.append(t)
    threads[0].join()


if __name__ == "__main__":
    main()

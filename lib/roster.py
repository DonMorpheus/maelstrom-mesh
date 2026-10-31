"""Public roster (no private keys / PSK) + live merge from wg dump."""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from lib.geo import lookup


def public_roster(data: dict[str, Any]) -> dict[str, Any]:
    hub = data["hub"]
    hosts = []
    for p in data.get("peers", []):
        overlay = p["address"].split("/")[0]
        hosts.append(
            {
                "name": p["name"],
                "os": p["os"],
                "overlay": overlay,
                "public": p["public"],
                "mode": p.get("mode", "persist"),
                "tag": p.get("tag", "victim"),
                "routes": p.get("routes") or [],
                "serve": p.get("serve") or "",
                "fqdn": f"{p['name']}.{data.get('domain', 'rt')}",
                "http": 8080,
                "role": p.get("role", "peer"),
                "tor": bool(p.get("tor")),
                "endpoints": p.get("endpoints") or [],
                "entry": p.get("role") == "hub",
                "exit": True,
                "socks": 1080,
            }
        )
    return {
        "name": data["name"],
        "network": data["network"],
        "endpoint": data["endpoint"],
        "endpoints": data.get("endpoints") or [data.get("endpoint")],
        "listen_port": data["listen_port"],
        "domain": data.get("domain", "rt"),
        "c2": data.get("c2") or {},
        "hub": {
            "name": hub["name"],
            "os": hub.get("os", "linux"),
            "overlay": hub["address"].split("/")[0],
            "public": hub["public"],
            "fqdn": f"hub.{data.get('domain', 'rt')}",
            "endpoints": data.get("endpoints") or [data.get("endpoint")],
            "entry": True,
            "exit": False,
            "socks": 0,
        },
        "hosts": hosts,
    }


def parse_wg_dump(text: str) -> dict[str, dict[str, Any]]:
    """pubkey -> {wan, handshake, rx, tx}. Drops interface private key line."""
    out: dict[str, dict[str, Any]] = {}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return out
    for ln in lines[1:]:
        parts = ln.split("\t")
        if len(parts) < 5:
            continue
        pub, _psk, endpoint, _allow, hs = parts[0], parts[1], parts[2], parts[3], parts[4]
        wan = ""
        if endpoint and endpoint != "(none)":
            wan = endpoint.rsplit(":", 1)[0].strip("[]")
        try:
            hs_i = int(hs)
        except ValueError:
            hs_i = 0
        out[pub] = {"wan": wan, "handshake": hs_i, "live": hs_i > 0}
    return out


def wg_dump_cmd() -> str:
    wg = shutil.which("wg")
    if not wg:
        return ""
    p = subprocess.run([wg, "show", "wg0", "dump"], capture_output=True, text=True, check=False)
    if p.returncode != 0:
        return ""
    return p.stdout


def decorate(roster: dict[str, Any], dump: dict[str, dict[str, Any]], cache_dir=None) -> dict[str, Any]:
    hub = roster["hub"]
    hub_wan = ""
    ep = roster.get("endpoint") or ""
    if ep:
        hub_wan = ep.rsplit(":", 1)[0]
    geo_h = lookup(hub_wan, cache_dir=cache_dir)
    hub["wan"] = geo_h.get("ip") or hub_wan
    hub["country"] = geo_h.get("country", "")
    hub["country_name"] = geo_h.get("country_name", "")
    hub["flag"] = geo_h.get("flag", "🏳️")
    hub["live"] = True
    for h in roster["hosts"]:
        st = dump.get(h["public"], {})
        wan = st.get("wan") or ""
        geo = lookup(wan, cache_dir=cache_dir) if wan else {"country": "", "country_name": "", "flag": "🏳️"}
        h["wan"] = wan
        h["handshake"] = st.get("handshake", 0)
        h["live"] = bool(st.get("live"))
        h["country"] = geo.get("country", "")
        h["country_name"] = geo.get("country_name", "")
        h["flag"] = geo.get("flag", "🏳️")
        h["rtt_ms"] = tcp_rtt_ms(h.get("overlay") or "", 1080 if h.get("socks") else 0)
    return roster


def tcp_rtt_ms(ip: str, port: int, timeout: float = 0.8) -> int | None:
    if not ip or not port:
        return None
    import socket
    import time

    t0 = time.monotonic()
    try:
        s = socket.create_connection((ip, port), timeout)
        s.close()
        return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None


def as_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, indent=2) + "\n"

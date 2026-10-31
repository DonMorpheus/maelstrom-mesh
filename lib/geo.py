"""Country code + flag for a WAN IP (exit/entry labels)."""
from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from pathlib import Path

_CACHE: dict[str, dict] = {}


def flag(cc: str) -> str:
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def _geoip_mod(ip: str) -> dict | None:
    try:
        import GeoIP  # type: ignore
    except ImportError:
        return None
    try:
        gi = GeoIP.open("/usr/share/GeoIP/GeoIP.dat", GeoIP.GEOIP_MEMORY_CACHE)
        cc = gi.country_code_by_addr(ip)
        name = gi.country_name_by_addr(ip)
    except Exception:
        return None
    if not cc:
        return None
    return {"country": cc.upper(), "country_name": name or cc, "source": "geoip.dat"}


def _ipapi(ip: str, cache_dir: Path | None) -> dict | None:
    path = None
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / "geo.json"
        if path.is_file():
            try:
                disk = json.loads(path.read_text(encoding="utf-8"))
                _CACHE.update({k: v for k, v in disk.items() if isinstance(v, dict)})
            except json.JSONDecodeError:
                pass
        if ip in _CACHE:
            return _CACHE[ip]
    url = "http://ip-api.com/json/" + urllib.parse.quote(ip) + "?fields=status,country,countryCode,query"
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = json.loads(r.read().decode("utf-8"))
    except Exception:
        return None
    if body.get("status") != "success":
        return None
    rec = {
        "country": str(body.get("countryCode") or "").upper(),
        "country_name": body.get("country") or "",
        "source": "ip-api",
    }
    if rec["country"]:
        _CACHE[ip] = rec
        if path:
            path.write_text(json.dumps(_CACHE, indent=0), encoding="utf-8")
    return rec if rec["country"] else None


def _resolve(host: str) -> str:
    host = host.strip().strip("[]")
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError:
        return host


def lookup(ip: str, cache_dir: Path | None = None) -> dict:
    ip = (ip or "").split("%")[0].strip()
    if ip and not ip.replace(".", "").isdigit():
        ip = _resolve(ip)
    if not ip or ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."):
        return {"country": "", "country_name": "", "flag": "🏳️", "source": "private"}
    rec = _geoip_mod(ip) or _ipapi(ip, cache_dir)
    if not rec:
        return {"country": "", "country_name": "unknown", "flag": "🏳️", "source": "none", "ip": ip}
    rec["flag"] = flag(rec.get("country") or "")
    rec["ip"] = ip
    return rec

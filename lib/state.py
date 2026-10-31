"""Encrypted mesh.json: hub + peers + PSK inventory."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.crypto import open_box, read_keyfile, seal, write_keyfile, new_mesh_key
from lib.keys import gen_keypair, gen_psk, pubkey

NET = "10.66.0.0/24"
HUB_HOST = "10.66.0.1"
LISTEN_PORT = 51820
KEEPALIVE = 25
SCHEMA = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Mesh:
    def __init__(self, out: Path) -> None:
        self.out = Path(out).resolve()
        self.key_path = self.out / "mesh.key"
        self.state_path = self.out / "mesh.json"
        self.data: dict[str, Any] = {}

    def exists(self) -> bool:
        return self.state_path.is_file() and self.key_path.is_file()

    def _load_key(self) -> bytes:
        if not self.key_path.is_file():
            raise FileNotFoundError(f"missing {self.key_path} — state is sealed")
        return read_keyfile(self.key_path)

    def load(self) -> dict[str, Any]:
        blob = self.state_path.read_bytes()
        raw = open_box(blob, self._load_key())
        self.data = json.loads(raw.decode("utf-8"))
        return self.data

    def save(self) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        if not self.key_path.is_file():
            write_keyfile(self.key_path, new_mesh_key())
        blob = seal(
            json.dumps(self.data, indent=2, sort_keys=False).encode("utf-8"),
            self._load_key(),
        )
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.state_path)
        try:
            self.state_path.chmod(0o600)
            self.out.chmod(0o700)
        except OSError:
            pass

    def init(
        self,
        name: str,
        endpoint: str,
        listen_port: int = LISTEN_PORT,
    ) -> dict[str, Any]:
        if self.exists() and not (self.out / ".force").exists():
            raise FileExistsError(f"{self.out} already has a mesh (use --force)")
        host, port = _split_endpoint(endpoint, listen_port)
        priv, pub = gen_keypair()
        self.data = {
            "schema": SCHEMA,
            "name": name,
            "network": NET,
            "listen_port": listen_port,
            "endpoint": f"{host}:{port}",
            "crypto": {
                "tunnel": "wireguard-noise-ik",
                "aead": "chacha20-poly1305",
                "dh": "x25519",
                "psk": "unique-per-peer",
                "state": "scrypt+xsalsa20-poly1305",
            },
            "created": utcnow(),
            "hub": {
                "name": "hub",
                "os": "linux",
                "address": f"{HUB_HOST}/24",
                "private": priv,
                "public": pub,
            },
            "peers": [],
            "revoked": [],
        }
        self.save()
        return self.data

    def next_ip(self) -> str:
        used = {HUB_HOST}
        for p in self.data.get("peers", []):
            used.add(p["address"].split("/")[0])
        for n in range(2, 255):
            ip = f"10.66.0.{n}"
            if ip not in used:
                return ip
        raise RuntimeError("10.66.0.0/24 exhausted")

    def add_peer(self, name: str, os_name: str) -> dict[str, Any]:
        name = name.strip().lower()
        if not name or any(p["name"] == name for p in self.data["peers"]):
            raise ValueError(f"peer name taken or empty: {name}")
        if name in ("hub", "out"):
            raise ValueError("reserved name")
        priv, pub = gen_keypair()
        ip = self.next_ip()
        peer = {
            "name": name,
            "os": os_name,
            "address": f"{ip}/32",
            "private": priv,
            "public": pub,
            "psk": gen_psk(),
            "created": utcnow(),
            "mode": "persist" if os_name in ("windows", "linux") else "session",
        }
        self.data["peers"].append(peer)
        self.save()
        return peer

    def revoke(self, name: str) -> dict[str, Any]:
        name = name.strip().lower()
        keep = []
        found = None
        for p in self.data["peers"]:
            if p["name"] == name:
                found = p
            else:
                keep.append(p)
        if not found:
            raise KeyError(name)
        self.data["peers"] = keep
        self.data.setdefault("revoked", []).append(
            {
                "name": found["name"],
                "public": found["public"],
                "when": utcnow(),
            }
        )
        self.save()
        return found

    def peer(self, name: str) -> dict[str, Any]:
        for p in self.data["peers"]:
            if p["name"] == name:
                return p
        raise KeyError(name)

    def public_view(self) -> dict[str, Any]:
        """GUI/API: no private keys, no PSKs."""
        d = self.data
        hub = d["hub"]
        return {
            "name": d["name"],
            "network": d["network"],
            "endpoint": d["endpoint"],
            "listen_port": d["listen_port"],
            "crypto": d.get("crypto", {}),
            "hub": {
                "name": hub["name"],
                "os": hub.get("os", "linux"),
                "address": hub["address"],
                "public": hub["public"],
            },
            "peers": [
                {
                    "name": p["name"],
                    "os": p["os"],
                    "address": p["address"],
                    "public": p["public"],
                    "created": p.get("created", ""),
                    "mode": p.get("mode", "session"),
                    "handshake": p.get("handshake", "unknown"),
                }
                for p in d["peers"]
            ],
            "revoked": d.get("revoked", []),
        }


def _split_endpoint(endpoint: str, default_port: int) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        host, _, rest = endpoint[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return endpoint, default_port


def assert_pubkey(node: dict[str, Any]) -> None:
    if pubkey(node["private"]) != node["public"]:
        raise RuntimeError(f"key pair broken for {node.get('name')}")

"""WireGuard Curve25519 keys (RFC 7748), same clamp as `wg genkey`."""
from __future__ import annotations

import base64
import os
import shutil
import subprocess

from nacl.bindings import crypto_scalarmult_base

WG_B64_LEN = 44  # 32 bytes → standard base64 with padding


def _clamp(raw: bytes) -> bytes:
    if len(raw) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    k = bytearray(raw)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(s: str) -> bytes:
    raw = base64.b64decode(s.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("expected 32-byte key")
    return raw


def to_hex(b64key: str) -> str:
    return b64d(b64key).hex()


def gen_private() -> str:
    return b64(_clamp(os.urandom(32)))


def pubkey(private_b64: str) -> str:
    pub = crypto_scalarmult_base(b64d(private_b64))
    return b64(pub)


def gen_keypair() -> tuple[str, str]:
    priv = gen_private()
    return priv, pubkey(priv)


def gen_psk() -> str:
    """Independent 32-byte PSK (not an X25519 scalar). One per hub↔peer pair."""
    return b64(os.urandom(32))


def wg_pubkey_cli(private_b64: str) -> str | None:
    """If `wg` is on PATH, return its pubkey (used as a lab check)."""
    wg = shutil.which("wg")
    if not wg:
        return None
    p = subprocess.run(
        [wg, "pubkey"],
        input=private_b64 + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        return None
    return p.stdout.strip()


def selftest() -> None:
    priv, pub = gen_keypair()
    if pubkey(priv) != pub:
        raise RuntimeError("pubkey mismatch")
    cli = wg_pubkey_cli(priv)
    if cli is not None and cli != pub:
        raise RuntimeError(f"wg pubkey mismatch: {cli} vs {pub}")
    psk = gen_psk()
    if psk == priv or len(b64d(psk)) != 32:
        raise RuntimeError("psk failed")

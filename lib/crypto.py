"""At-rest protection for mesh.json.

Tunnel crypto is WireGuard (Noise_IK, ChaCha20-Poly1305, per-peer PSK).
This box only hides the operator state file on disk.

Format: magic || salt(16) || nacl SecretBox(nonce||ct||mac)
KDF: scrypt(N=2**15, r=8, p=1, dklen=32) over mesh.key bytes.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

MAGIC = b"RIPTIDE1"
SALT_LEN = 16
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def new_mesh_key() -> bytes:
    return os.urandom(32)


def _kdf(mesh_key: bytes, salt: bytes) -> bytes:
    if len(mesh_key) != 32:
        raise ValueError("mesh.key must be 32 bytes")
    return hashlib.scrypt(
        mesh_key,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )


def seal(plaintext: bytes, mesh_key: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    box = SecretBox(_kdf(mesh_key, salt))
    return MAGIC + salt + box.encrypt(plaintext)


def open_box(blob: bytes, mesh_key: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a Riptide state file (missing RIPTIDE1 magic)")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_LEN]
    ct = blob[len(MAGIC) + SALT_LEN :]
    try:
        return SecretBox(_kdf(mesh_key, salt)).decrypt(ct)
    except CryptoError as e:
        raise ValueError("wrong mesh.key or corrupted state") from e


def write_keyfile(path: Path, key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_keyfile(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError(f"{path} is not a 32-byte mesh.key")
    return key

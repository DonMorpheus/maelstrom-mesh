"""Operator accounts on the hub (admin vs operator)."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
TOKEN_TTL = 12 * 3600
ROLES = ("admin", "operator")

# token -> {name, role, exp}
_TOKENS: dict[str, dict[str, Any]] = {}


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    import base64

    return base64.b64decode(s.encode("ascii"))


def hash_password(password: str) -> dict[str, str]:
    salt = os.urandom(16)
    h = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    return {"kdf": "scrypt", "salt": _b64(salt), "hash": _b64(h)}


def verify_password(rec: dict[str, Any], password: str) -> bool:
    try:
        salt = _b64d(rec["salt"])
        want = _b64d(rec["hash"])
    except Exception:
        return False
    got = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    return secrets.compare_digest(got, want)


def load_users(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    return list(doc.get("users") or [])


def save_users(path: Path, users: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"users": users}, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def upsert_user(path: Path, name: str, password: str, role: str) -> None:
    name = name.strip()
    role = role.strip().lower()
    if role not in ROLES:
        raise ValueError(f"role must be admin|operator")
    if not name or not password:
        raise ValueError("name/password empty")
    users = load_users(path)
    rec = {"name": name, "role": role, **hash_password(password)}
    users = [u for u in users if u.get("name") != name]
    users.append(rec)
    save_users(path, users)


def login(path: Path, name: str, password: str) -> dict[str, Any] | None:
    name = (name or "").strip()
    for u in load_users(path):
        if u.get("name") != name:
            continue
        if not verify_password(u, password):
            return None
        tok = secrets.token_urlsafe(32)
        _TOKENS[tok] = {
            "name": u["name"],
            "role": u.get("role") or "operator",
            "exp": time.time() + TOKEN_TTL,
        }
        return {"token": tok, "name": u["name"], "role": u.get("role") or "operator"}
    return None


def session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    rec = _TOKENS.get(token)
    if not rec:
        return None
    if rec["exp"] < time.time():
        _TOKENS.pop(token, None)
        return None
    return rec

"""Tiny overlay DNS: name.rt / name → 10.66.0.X A records."""
from __future__ import annotations

import socket
import struct
import threading
from typing import Callable


def _qname(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    seen = offset
    for _ in range(32):
        if offset >= len(data):
            break
        l = data[offset]
        if l == 0:
            if not jumped:
                offset += 1
            return ".".join(labels).lower(), offset if not jumped else seen
        if l & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((l & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                seen = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + l].decode("ascii", "ignore"))
        offset += l
    return "", offset


def reply_a(req: bytes, table: dict[str, str]) -> bytes | None:
    if len(req) < 12:
        return None
    flags = struct.unpack("!H", req[2:4])[0]
    opcode = (flags >> 11) & 0xF
    if opcode != 0:
        return None
    name, off = _qname(req, 12)
    if not name or off + 4 > len(req):
        return None
    qtype, _qclass = struct.unpack("!HH", req[off : off + 4])
    ip = table.get(name) or table.get(name.split(".", 1)[0])
    id_ = req[:2]
    qsec = req[12 : off + 4]
    if qtype not in (1, 255) or not ip:  # A or ANY
        # NXDOMAIN-ish: no error, empty answer so clients fall through
        hdr = id_ + struct.pack("!HHHHH", 0x8400, 1, 0, 0, 0)
        return hdr + qsec
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4:
        return None
    hdr = id_ + struct.pack("!HHHHH", 0x8400, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + bytes(parts)
    return hdr + qsec + ans


def serve_dns(bind: str, table_fn: Callable[[], dict[str, str]]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, 53))
    print(f"[+] dns udp://{bind}:53")

    def loop() -> None:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                table = table_fn()
                raw = reply_a(data, table)
                if raw:
                    sock.sendto(raw, addr)
            except OSError:
                return

    threading.Thread(target=loop, daemon=True).start()

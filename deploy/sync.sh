#!/usr/bin/env bash
# Push hub/wg0.conf and wg syncconf — add extra hub peers without bouncing wg0.
# Does NOT wg-quick down/up. Does NOT touch nginx/C2/UFW.
#
#   python3 mesh.py hub --out ./riptide-out --name harry-hub --os windows --endpoints 192.168.0.135:51820
#   python3 mesh.py sync --out ./riptide-out --remote rt-vps --yes
set -euo pipefail

REMOTE=""
OUT=""
YES=0
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20)
SCP=(scp -o BatchMode=yes -o ConnectTimeout=20)

usage() {
  cat <<'EOF'
deploy/sync.sh — apply extra WireGuard peers on a live hub (syncconf)

  --remote USER@HOST   SSH target
  --out DIR            mesh.py output (hub/wg0.conf)
  --yes                actually copy + syncconf

Leaves wg0 up. Leaves :22 and HTTPS C2 alone.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote) REMOTE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$REMOTE" && -n "$OUT" ]] || { usage; exit 2; }

OUT="$(cd "$OUT" && pwd)"
CONF=""
for c in "$OUT/hub/wg0.conf" "$OUT/hub-wg0.conf"; do
  if [[ -f "$c" ]]; then
    CONF="$c"
    break
  fi
done
[[ -n "$CONF" ]] || { echo "[-] no hub conf in $OUT" >&2; exit 2; }

echo "[*] remote  $REMOTE"
echo "[*] conf    $CONF"
echo "[*] action  install wg0.conf + wg syncconf (no bounce)"

if [[ "$YES" != 1 ]]; then
  echo "[!] pass --yes to apply"
  exit 0
fi

echo "[*] copy hub conf"
"${SCP[@]}" "$CONF" "$REMOTE:/tmp/riptide-wg0.conf"

"${SSH[@]}" "$REMOTE" bash -s <<'REMOTE'
set -euo pipefail
if ! ip link show wg0 >/dev/null 2>&1; then
  echo "[-] wg0 is down — use deploy/hub.sh, not sync.sh" >&2
  exit 2
fi
install -d -m 700 /etc/wireguard
install -m 600 /tmp/riptide-wg0.conf /etc/wireguard/wg0.conf
shred -u /tmp/riptide-wg0.conf 2>/dev/null || rm -f /tmp/riptide-wg0.conf
wg syncconf wg0 <(wg-quick strip /etc/wireguard/wg0.conf)
echo '--- wg show ---'
wg show
REMOTE

echo "[+] syncconf done on $REMOTE (wg0 stayed up)"

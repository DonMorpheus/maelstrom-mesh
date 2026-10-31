#!/usr/bin/env bash
# Deploy Riptide hub (WireGuard :51820/udp) to a remote Linux VPS.
# Same box can keep HTTPS C2 on :443. This script does not touch nginx/C2.
#
#   python3 mesh.py init --name ops --endpoint YOUR.VPS.IP --out ./riptide-out
#   python3 mesh.py peer --out ./riptide-out --name kali --os linux
#   ./deploy/hub.sh --remote root@YOUR.VPS.IP --out ./riptide-out --yes
#
# Safety: does not ufw --force enable/reset, does not lock SSH to wg0.
set -euo pipefail

REMOTE=""
OUT=""
PORT=51820
YES=0
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20)
SCP=(scp -o BatchMode=yes -o ConnectTimeout=20)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
deploy/hub.sh — install Riptide hub on a remote VPS

  --remote USER@HOST   SSH target (or ~/.ssh/config Host)
  --out DIR            mesh.py output (must contain hub/wg0.conf)
  --port N             UDP listen (default 51820)
  --yes                actually install (otherwise print plan and exit)

Installs wireguard, writes /etc/wireguard/wg0.conf (mode 600),
sysctl ip_forward, ufw allow <port>/udp if ufw is active,
enables wg-quick@wg0. Leaves :22 and HTTPS C2 alone.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote) REMOTE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
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
[[ -n "$CONF" ]] || { echo "[-] no hub conf in $OUT (run mesh.py init)" >&2; exit 2; }
grep -q 'ListenPort' "$CONF" || { echo "[-] $CONF missing ListenPort" >&2; exit 2; }

echo "[*] remote  $REMOTE"
echo "[*] conf    $CONF"
echo "[*] wan udp $PORT"
echo "[*] leaves  ssh/22 and any :80/:443 C2 untouched"

if [[ "$YES" != 1 ]]; then
  echo "[!] pass --yes to install"
  exit 0
fi

echo "[*] ssh probe"
"${SSH[@]}" "$REMOTE" 'uname -a && command -v apt-get >/dev/null'

echo "[*] copy hub conf"
"${SCP[@]}" "$CONF" "$REMOTE:/tmp/riptide-wg0.conf"

# shellcheck disable=SC2029
"${SSH[@]}" "$REMOTE" "PORT=$PORT bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v wg >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y wireguard
fi
install -d -m 700 /etc/wireguard
install -m 600 /tmp/riptide-wg0.conf /etc/wireguard/wg0.conf
shred -u /tmp/riptide-wg0.conf 2>/dev/null || rm -f /tmp/riptide-wg0.conf
printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-riptide.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/udp" comment 'riptide-wg' || true
fi
wg-quick down wg0 2>/dev/null || true
systemctl enable wg-quick@wg0 >/dev/null
wg-quick up wg0
echo '--- wg show ---'
wg show
echo '--- udp ---'
ss -ulnp | grep -E ":${PORT}\\b" || true
REMOTE

echo "[+] hub up on $REMOTE  udp/$PORT"
if [[ -f "$OUT/hub/roster.json" ]]; then
  echo "[*] roster daemon"
  "$ROOT/deploy/roster.sh" --remote "$REMOTE" --out "$OUT" --yes
fi
echo "[+] peer from Kali: ./agent/riptide-agent --config $OUT/peers/<name>.conf"
echo "[+] GUI: python3 mesh.py gui --out $OUT --hub-ssh $REMOTE"

#!/usr/bin/env bash
# Push public roster + rosterd to a hub. Does not bounce wg0.
# Binds 127.0.0.1:7668 and 10.66.0.1:7668 — not WAN.
set -euo pipefail
REMOTE=""
OUT=""
YES=0
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20)
SCP=(scp -o BatchMode=yes -o ConnectTimeout=20)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote) REMOTE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --yes) YES=1; shift ;;
    *) echo "usage: deploy/roster.sh --remote HOST --out DIR [--yes]" >&2; exit 2 ;;
  esac
done
[[ -n "$REMOTE" && -n "$OUT" ]] || { echo "need --remote and --out" >&2; exit 2; }
OUT="$(cd "$OUT" && pwd)"
ROSTER="$OUT/hub/roster.json"
[[ -f "$ROSTER" ]] || { echo "[-] missing $ROSTER (mesh.py init/peer)" >&2; exit 2; }

echo "[*] roster -> $REMOTE  (127.0.0.1:7668 + wg0)"
if [[ "$YES" != 1 ]]; then
  echo "[!] pass --yes"
  exit 0
fi

"${SSH[@]}" "$REMOTE" 'install -d -m 755 /usr/local/lib/riptide/lib /etc/riptide /var/cache/riptide'
"${SCP[@]}" "$ROSTER" "$REMOTE:/etc/riptide/roster.json"
"${SCP[@]}" "$ROOT/lib/__init__.py" "$ROOT/lib/geo.py" "$ROOT/lib/roster.py" \
  "$REMOTE:/usr/local/lib/riptide/lib/"
"${SCP[@]}" "$ROOT/deploy/rosterd.py" "$REMOTE:/usr/local/lib/riptide/rosterd.py"
"${SCP[@]}" "$ROOT/persist/riptide-roster.service" \
  "$REMOTE:/etc/systemd/system/riptide-roster.service"
"${SSH[@]}" "$REMOTE" 'chmod 755 /usr/local/lib/riptide/rosterd.py
systemctl daemon-reload
systemctl enable --now riptide-roster
systemctl restart riptide-roster
sleep 1
curl -sS --max-time 3 http://127.0.0.1:7668/api/hosts | head -c 400
echo'
echo "[+] roster live"

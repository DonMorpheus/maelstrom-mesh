#!/usr/bin/env bash
# Apply hub-wg0.conf on THIS box. CONFIRM=YES required.
# Do not point this at a WAN VPS until the operator says so.
set -euo pipefail
if [[ "${CONFIRM:-}" != "YES" ]]; then
  echo "refusing: CONFIRM=YES required" >&2
  exit 2
fi
CONF_SRC="${1:-./hub-wg0.conf}"
install -d -m 700 /etc/wireguard
install -m 600 "$CONF_SRC" /etc/wireguard/wg0.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
wg show

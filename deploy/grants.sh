#!/usr/bin/env bash
# Overlay forwarding + victim-victim DROP. Does not touch WAN 443/22/51820.
set -euo pipefail
OPS="${OPS:-}"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow in on wg0 to any port 53 proto udp comment 'riptide-dns' >/dev/null || true
  ufw route allow in on wg0 out on wg0 comment 'riptide-overlay' >/dev/null || true
fi
iptables -N RIPTIDE 2>/dev/null || true
iptables -F RIPTIDE
iptables -A RIPTIDE -s 10.66.0.0/24 -d 10.66.0.1 -j RETURN
for ip in $OPS; do
  iptables -A RIPTIDE -s "${ip}/32" -d 10.66.0.0/24 -j RETURN
  iptables -A RIPTIDE -s 10.66.0.0/24 -d "${ip}/32" -j RETURN
done
iptables -A RIPTIDE -s 10.66.0.0/24 -d 10.66.0.0/24 -j DROP
if ! iptables -C FORWARD -i wg0 -j RIPTIDE 2>/dev/null; then
  iptables -I FORWARD -i wg0 -j RIPTIDE
fi
echo "[+] grants OPS=${OPS:-none}"

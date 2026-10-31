#!/usr/bin/env bash
# WAN: 80/443 TCP + 51820/udp. SSH and operator WSS only in on wg0.
# Does not --force enable or --force reset.
set -euo pipefail
if [[ "${CONFIRM:-}" != "YES" ]]; then
  echo "refusing: set CONFIRM=YES after reviewing rules" >&2
  exit 2
fi
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp comment 'http-acme'
ufw allow 443/tcp comment 'https-edge'
ufw allow 51820/udp comment 'riptide-wg'
ufw allow in on wg0 to any port 22 proto tcp comment 'ssh-overlay'
ufw allow in on wg0 to any port 40056 proto tcp comment 'op-wss-overlay'
ufw allow in on wg0 to any port 7668 proto tcp comment 'riptide-connect'
echo "[+] rules queued. enable yourself: ufw enable"
ufw status verbose

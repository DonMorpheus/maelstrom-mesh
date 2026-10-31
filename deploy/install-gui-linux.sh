#!/usr/bin/env bash
# Install Riptide Connect on this Linux user (no root required).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
APP="$PREFIX/share/applications"
SHARE="$PREFIX/share/riptide"
mkdir -p "$BIN" "$APP" "$SHARE"
install -m 755 "$ROOT/deploy/riptide-gui" "$BIN/riptide-gui"
install -m 644 "$ROOT/assets/logo.jpg" "$SHARE/logo.jpg"
cat > "$APP/riptide.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Riptide
Comment=Connect to the Riptide hub
Exec=$BIN/riptide-gui
Icon=$SHARE/logo.jpg
Terminal=false
Categories=Network;
EOF
if command -v update-desktop-database >/dev/null; then
  update-desktop-database "$APP" 2>/dev/null || true
fi
echo "[+] riptide-gui -> $BIN/riptide-gui"
echo "[+] desktop     -> $APP/riptide.desktop"
echo "[+] run: riptide-gui     (admin SSH tunnel to hub)"
echo "[+]      riptide-gui --overlay   (already on 10.66.0.0/24)"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "[!] add $BIN to PATH" ;;
esac

#!/data/data/com.termux/files/usr/bin/bash
# WiFuX (clean rebuild) installer for Termux — registers the global `wifux` command.
# For authorized security testing only.

GREEN="\033[1;32m"; YELLOW="\033[1;33m"; CYAN="\033[1;36m"; RESET="\033[0m"

echo -e "${GREEN}[+] Installing dependencies…${RESET}"
pkg install -y root-repo tur-repo >/dev/null 2>&1 || true
pkg update -y
pkg install -y python git wpa-supplicant pixiewps iw

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$PREFIX/bin/wifux"

echo -e "${GREEN}[+] Registering 'wifux' command…${RESET}"
cat > "$BIN" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
# WiFuX launcher — runs the clean rebuild (python -m wifux)
cd "$REPO_DIR" || exit 1
exec python -m wifux "\$@"
EOF
chmod +x "$BIN"

echo -e "\n${GREEN}[✓] Installed. The 'wifux' command is ready.${RESET}"
echo -e "${CYAN}────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}wifux --pins -b <BSSID>${RESET}        offline PIN candidates (no root)"
echo -e "  ${YELLOW}wifux --list-sessions${RESET}          list saved sessions"
echo -e "  ${YELLOW}su -c 'wifux -i wlan0 -K'${RESET}      scan + Pixie Dust (needs root)"
echo -e "  ${YELLOW}su -c 'wifux -i wlan0 -b <BSSID> -B --html-report'${RESET}"
echo -e "${CYAN}────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Only test networks you own or are authorized to test.${RESET}\n"

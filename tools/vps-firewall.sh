#!/usr/bin/env bash
# Buka port server MLBB lokal di VPS lewat ufw.
#
# Pemakaian:
#   ./tools/vps-firewall.sh
#   SSH_PORT=2222 ./tools/vps-firewall.sh   # bila SSH bukan di port 22
#
# Port yang dibuka:
#   TCP 30021, 30071, 30101, 10003, 30103
#   UDP 30101, 10003, 30103, 7000, 8000, 9000
#
# `ufw --force enable` dipakai supaya tidak menunggu konfirmasi interaktif.
# Port SSH ikut diizinkan lebih dulu agar tidak mengunci diri sendiri.
set -euo pipefail

TCP_PORTS=(30021 30071 30101 10003 30103)
UDP_PORTS=(30101 10003 30103 7000 8000 9000)

if ! command -v ufw >/dev/null 2>&1; then
  echo "[!] ufw tidak ditemukan. Install dulu: sudo apt install ufw" >&2
  exit 1
fi

# Deteksi port SSH dari sesi saat ini bila tidak diberikan lewat env.
SSH_PORT="${SSH_PORT:-}"
if [ -z "$SSH_PORT" ] && [ -n "${SSH_CONNECTION:-}" ]; then
  SSH_PORT="${SSH_CONNECTION##* }"
fi
SSH_PORT="${SSH_PORT:-22}"

echo "[*] Izinkan SSH tcp/${SSH_PORT} (anti-lockout)"
sudo ufw allow "${SSH_PORT}/tcp" comment 'ssh anti-lockout' >/dev/null

for p in "${TCP_PORTS[@]}"; do
  echo "[+] ufw allow ${p}/tcp"
  sudo ufw allow "${p}/tcp" >/dev/null
done

for p in "${UDP_PORTS[@]}"; do
  echo "[+] ufw allow ${p}/udp"
  sudo ufw allow "${p}/udp" >/dev/null
done

if sudo ufw status | grep -q '^Status: active'; then
  echo "[i] ufw sudah aktif"
else
  echo "[*] Aktifkan ufw"
  sudo ufw --force enable >/dev/null
fi

echo
sudo ufw status numbered

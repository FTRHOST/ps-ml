#!/usr/bin/env bash
#
# hotspot.sh — jadikan device ini hotspot dan arahkan semua kliennya ke server
# lokal di PC.
#
# Latar belakang:
#   Perangkat yang tidak root tidak bisa dipasangi iptables sendiri. Solusinya,
#   device ini menjadi hotspot (gateway), lalu aturan DNAT dipasang di device
#   (chain PREROUTING) sehingga SEMUA perangkat yang join otomatis memakai
#   server lokal PC. PC cukup menjadi salah satu klien hotspot.
#
# Pemakaian:
#   ./tools/hotspot.sh on       # cek hotspot + pasang DNAT untuk device & klien
#   ./tools/hotspot.sh status   # SSID, IP, daftar klien, aturan redirect
#   ./tools/hotspot.sh clients  # daftar perangkat yang tersambung
#   ./tools/hotspot.sh off      # lepas semua pengalihan
#
# Catatan: hotspot sendiri diaktifkan dari Settings Android (Personal Hotspot).
# Skrip ini membuka halaman tersebut bila hotspot belum aktif.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIRECT="${SCRIPT_DIR}/redirect.sh"

ap_if() {
  adb shell ip -o -4 addr show 2>/dev/null \
    | awk '$2 ~ /^ap[0-9]+$/ {print $2; exit}'
}

ap_ip() {
  local ifc="$1"
  adb shell ip -o -4 addr show "${ifc}" 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1 | head -n1
}

ssid() {
  adb shell dumpsys wifi 2>/dev/null \
    | sed -n 's/.*mCurrentSoftApConfiguration: ssid = "\(.*\)"/\1/p' \
    | head -n1
}

clients() {
  local ifc="$1"
  adb shell ip neigh show dev "${ifc}" 2>/dev/null \
    | awk 'NF >= 3 {printf "  %-18s %-20s %s\n", $1, $3, $4}'
}

open_hotspot_settings() {
  adb shell am start -a android.settings.TETHER_SETTINGS >/dev/null 2>&1 || true
}

case "${1:-}" in
  on)
    IFACE="$(ap_if)"
    if [ -z "$IFACE" ]; then
      echo "[!] Hotspot belum aktif."
      echo "    Aktifkan Settings > Personal Hotspot, lalu jalankan ulang:"
      echo "    $0 on"
      open_hotspot_settings
      exit 1
    fi
    echo "[*] Hotspot aktif: ${IFACE} ($(ap_ip "${IFACE}")) SSID=$(ssid)"
    echo "[*] Memasang DNAT untuk device ini dan semua klien hotspot..."
    "${REDIRECT}" wifi
    echo
    echo "[✓] Perangkat yang join hotspot ini akan masuk ke server lokal PC."
    echo "    Klien saat ini:"
    clients "${IFACE}"
    ;;
  status)
    IFACE="$(ap_if)"
    if [ -z "$IFACE" ]; then
      echo "[i] Hotspot tidak aktif."
    else
      echo "[i] Hotspot : ${IFACE} ($(ap_ip "${IFACE}")) SSID=$(ssid)"
      echo "[i] Klien   :"
      clients "${IFACE}"
    fi
    echo
    "${REDIRECT}" status
    ;;
  clients)
    IFACE="$(ap_if)"
    if [ -z "$IFACE" ]; then
      echo "[i] Hotspot tidak aktif."
      exit 1
    fi
    clients "${IFACE}"
    ;;
  off)
    "${REDIRECT}" off
    ;;
  *)
    echo "pemakaian: $0 on|status|clients|off" >&2
    exit 2
    ;;
esac

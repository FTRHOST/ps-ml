#!/usr/bin/env bash
#
# redirect-watch.sh — jaga aturan DNAT tetap terpasang dan tetap menunjuk IP PC.
#
# Android/netd dapat membersihkan aturan nat kustom saat jaringan berubah
# (WiFi roam, hotspot restart, dsb.). Skrip ini memeriksa secara berkala dan
# memasang ulang `./tools/redirect.sh wifi` bila:
#   - jumlah aturan berkurang, atau
#   - IP PC berubah (aturan masih menunjuk alamat lama).
#
# Pemakaian:
#   ./tools/redirect-watch.sh            # interval 30 detik
#   ./tools/redirect-watch.sh 10         # interval 10 detik
#   nohup ./tools/redirect-watch.sh >/tmp/opencode/redirect-watch.log 2>&1 &
#
# Hentikan dengan Ctrl-C, atau `kill <PID>`.
set -euo pipefail

INTERVAL="${1:-30}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

detect_host_ip() {
  ip route get 1.1.1.1 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

detect_ap_if() {
  adb shell ip -o -4 addr show 2>/dev/null \
    | awk '$2 ~ /^(ap|swlan|softap|wlan[1-9])/ {print $2; exit}'
}

while true; do
  HOST_IP="$(detect_host_ip || true)"
  AP_IF="$(detect_ap_if || true)"
  if [ -n "${AP_IF}" ]; then
    EXPECTED_TOTAL=12   # 4 OUTPUT + 4 PREROUTING + 4 POSTROUTING
    EXPECTED_DNAT=8     # 4 OUTPUT + 4 PREROUTING
  else
    EXPECTED_TOTAL=4    # hanya OUTPUT
    EXPECTED_DNAT=4
  fi

  RULES="$(python3 "${SCRIPT_DIR}/rootcmd.py" \
    "iptables -t nat -S 2>/dev/null" 2>/dev/null || true)"

  TOTAL=$(printf '%s\n' "${RULES}" | grep -c 'mlbb-local-server' || true)
  MATCH=0
  if [ -n "${HOST_IP}" ]; then
    MATCH=$(printf '%s\n' "${RULES}" \
      | grep -c -- "--to-destination ${HOST_IP}:" || true)
  fi
  TOTAL=${TOTAL:-0}
  MATCH=${MATCH:-0}

  if [ "${TOTAL}" -lt "${EXPECTED_TOTAL}" ] || [ "${MATCH}" -lt "${EXPECTED_DNAT}" ]; then
    echo "[watch] $(date +%H:%M:%S) aturan=${TOTAL}/${EXPECTED_TOTAL} ip=${MATCH}/${EXPECTED_DNAT} (PC=${HOST_IP:-?}), pasang ulang..."
    "${SCRIPT_DIR}/redirect.sh" wifi >/dev/null 2>&1 || true
  fi
  sleep "${INTERVAL}"
done

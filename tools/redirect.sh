#!/usr/bin/env bash
#
# redirect.sh — alihkan trafik TCP port game dari device ke server lokal di PC.
#
# Kenapa memakai NAT di device (bukan mengubah paket):
#   PRD N1 melarang relay memodifikasi byte. Kita TIDAK menyentuh payload;
#   kita hanya mengubah TUJUAN koneksi di device milik sendiri, lalu meneruskan
#   byte-nya apa adanya ke server lokal. Setara dengan menulis /etc/hosts, tetapi
#   port zone memakai IP sehingga hosts tidak cukup.
#
# Dua jalur yang didukung:
#   on   : app -> iptables REDIRECT 127.0.0.1 -> adb reverse -> PC (butuh USB/adb)
#   wifi : app -> iptables DNAT <IP-PC> -> PC lewat LAN (tanpa adb reverse)
#
# Pada mode wifi, bila device sedang menjadi hotspot, aturan PREROUTING juga
# dipasang supaya perangkat lain yang tersambung ke hotspot tersebut otomatis
# memakai server lokal (tanpa root di perangkat klien).
#
# Pemakaian:
#   ./tools/redirect.sh on                   # USB/adb (perilaku lama)
#   ./tools/redirect.sh wifi                 # LAN, IP PC dideteksi otomatis
#   ./tools/redirect.sh wifi 192.168.1.50    # LAN, IP PC eksplisit
#   ./tools/redirect.sh off                  # matikan semua pengalihan
#   ./tools/redirect.sh status
#
# Catatan:
#   - Device yang menjalankan skrip ini harus root (memasang iptables).
#   - Server PC harus mendengarkan 0.0.0.0 (default server/index.js) dan
#     firewall PC mengizinkan port 30021/30071/30101/10003.
#   - Aturan bertahan sampai reboot. Setelah reboot/IP PC berubah, jalankan
#     ulang `./tools/redirect.sh wifi`.
set -euo pipefail

PORTS=(30021 30071 30101 10003)   # Auth + Zone; beda versi klien beda port
COMMENT="mlbb-local-server"       # penanda aturan milik skrip ini
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTCMD="python3 ${SCRIPT_DIR}/rootcmd.py"

# Hapus aturan milik skrip ini + sisa versi lama, dalam SATU panggilan rootcmd.
# Banyak perintah digabung supaya reapply cepat (hindari spawn frida per aturan).
flush_rules() {
  local cmd
  cmd='for t in OUTPUT PREROUTING POSTROUTING; do '
  cmd+='while iptables -t nat -S "$t" | grep -q mlbb-local-server; do '
  cmd+='r=$(iptables -t nat -S "$t" | grep mlbb-local-server | head -n1); '
  cmd+='r=${r#-A }; iptables -t nat -D $r; done; done; '
  cmd+="for p in ${PORTS[*]}; do "
  cmd+='iptables -t nat -D OUTPUT -p tcp --dport $p -j REDIRECT --to-ports $p 2>/dev/null; '
  cmd+='while iptables -t nat -S OUTPUT | grep -q -- "--dport $p -j DNAT"; do '
  cmd+='r=$(iptables -t nat -S OUTPUT | grep -- "--dport $p -j DNAT" | head -n1); '
  cmd+='r=${r#-A }; iptables -t nat -D $r; done; done'
  $ROOTCMD "$cmd" >/dev/null 2>&1 || true
}

detect_host_ip() {
  # IP sumber yang dipakai PC untuk keluar; ini yang bisa dijangkau device.
  ip route get 1.1.1.1 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

# Cari interface hotspot di device (mis. ap0), tanpa syarat satu subnet dengan PC.
detect_ap_if() {
  adb shell ip -o -4 addr show 2>/dev/null \
    | awk '$2 ~ /^(ap|swlan|softap|wlan[1-9])/ {print $2; exit}'
}

# Interface yang dipakai device untuk keluar menuju IP PC.
detect_route_if() {
  local host_ip="$1"
  adb shell ip route get "${host_ip}" 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}'
}

# Pasang aturan tambahan (dipanggil setelah flush_rules).
apply_wifi_rules() {
  local host_ip="$1" ap_if="$2" route_if="$3" cmd="" p
  for p in "${PORTS[@]}"; do
    cmd+="iptables -t nat -A OUTPUT -p tcp --dport ${p} -j DNAT --to-destination ${host_ip}:${p} -m comment --comment ${COMMENT}; "
  done
  if [ -n "${ap_if}" ]; then
    for p in "${PORTS[@]}"; do
      # Kecualikan trafik dari PC sendiri: kalau PC menjalankan relay ke server
      # resmi, paketnya tidak boleh dipantulkan balik oleh DNAT hotspot.
      cmd+="iptables -t nat -A PREROUTING ! -s ${host_ip} -i ${ap_if} -p tcp --dport ${p} -j DNAT --to-destination ${host_ip}:${p} -m comment --comment ${COMMENT}; "
    done
    # MASQUERADE supaya balasan PC kembali lewat device (conntrack), bukan
    # langsung ke klien. Interface keluar bisa ap0 (PC di hotspot yang sama)
    # atau wlan0 (PC di WiFi upstream).
    local masq_if="${route_if:-$ap_if}"
    for p in "${PORTS[@]}"; do
      cmd+="iptables -t nat -A POSTROUTING -o ${masq_if} -p tcp -d ${host_ip} --dport ${p} -j MASQUERADE -m comment --comment ${COMMENT}; "
    done
  fi
  cmd="${cmd%; }"
  $ROOTCMD "$cmd" >/dev/null
}

apply_usb_rules() {
  local cmd="" p
  for p in "${PORTS[@]}"; do
    cmd+="iptables -t nat -A OUTPUT -p tcp --dport ${p} -j REDIRECT --to-ports ${p}; "
  done
  cmd="${cmd%; }"
  $ROOTCMD "$cmd" >/dev/null
}

case "${1:-}" in
  on)
    flush_rules
    for p in "${PORTS[@]}"; do
      echo "[*] adb reverse tcp:${p} -> PC tcp:${p}"
      adb reverse "tcp:${p}" "tcp:${p}" >/dev/null
    done
    apply_usb_rules
    for p in "${PORTS[@]}"; do
      echo "[+] port ${p} -> relay (adb reverse)"
    done
    ;;
  wifi)
    HOST_IP="${2:-}"
    if [ -z "$HOST_IP" ]; then
      HOST_IP="$(detect_host_ip)"
    fi
    if [ -z "$HOST_IP" ]; then
      echo "[!] tidak bisa mendeteksi IP PC. Jalankan: $0 wifi <IP-PC>" >&2
      exit 2
    fi
    echo "[*] server lokal PC: ${HOST_IP}"

    # Lepas jalur adb supaya terbukti murni lewat LAN.
    for p in "${PORTS[@]}"; do
      adb reverse --remove "tcp:${p}" >/dev/null 2>&1 || true
    done

    AP_IF="$(detect_ap_if)"
    ROUTE_IF="$(detect_route_if "${HOST_IP}")"
    flush_rules
    apply_wifi_rules "${HOST_IP}" "${AP_IF}" "${ROUTE_IF}"

    for p in "${PORTS[@]}"; do
      echo "[+] port ${p} -> ${HOST_IP}:${p} (LAN)"
    done
    if [ -n "$AP_IF" ]; then
      echo "[*] hotspot terdeteksi: ${AP_IF}; perangkat lain ikut diarahkan"
      echo "    jalur ke PC lewat: ${ROUTE_IF:-${AP_IF}}"
    else
      echo "[i] tidak ada interface hotspot; hanya perangkat ini yang diarahkan."
    fi
    ;;
  off)
    flush_rules
    for p in "${PORTS[@]}"; do
      adb reverse --remove "tcp:${p}" >/dev/null 2>&1 || true
      echo "[+] port ${p} dilepas (kembali ke server resmi)"
    done
    ;;
  status)
    echo "== adb reverse =="; adb reverse --list || true
    echo "== iptables nat OUTPUT =="; $ROOTCMD "iptables -t nat -L OUTPUT -n -v" || true
    echo "== iptables nat PREROUTING =="; $ROOTCMD "iptables -t nat -L PREROUTING -n -v" || true
    echo "== iptables nat POSTROUTING =="; $ROOTCMD "iptables -t nat -L POSTROUTING -n -v" || true
    echo "== IP PC (terdeteksi) =="; detect_host_ip || true
    ;;
  *)
    echo "pemakaian: $0 on|wifi [IP-PC]|off|status" >&2
    exit 2
    ;;
esac

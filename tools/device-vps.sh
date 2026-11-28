#!/usr/bin/env bash
# Pasang aturan DNAT di HP Android root agar trafik game masuk ke server VPS.
#
# Script ini dijalankan dari PC (butuh adb + frida-server di HP). Perintah
# iptables dikirim sebagai root lewat tools/rootcmd.py, karena device ini tidak
# punya binary `su` dan `adb root` ditolak.
#
# Pemakaian:
#   ./tools/device-vps.sh            # pasang aturan (default)
#   ./tools/device-vps.sh status     # lihat aturan
#   ./tools/device-vps.sh off        # hapus aturan milik script ini
#
# Konfigurasi ada di blok di bawah. Bisa juga ditimpa lewat environment,
# misalnya: VPS_IP=203.0.113.10 ./tools/device-vps.sh
set -euo pipefail

# ========================== KONFIGURASI ==========================
VPS_IP="${VPS_IP:-1.2.3.4}"                      # <-- GANTI IP VPS ANDA
TCP_PORTS="${TCP_PORTS:-30021 30071 30101 10003 30103}"
UDP_PORTS="${UDP_PORTS:-30101 10003 30103 7000 8000 9000}"
AP_IF="${AP_IF:-}"                               # kosong = auto-detect ap0/softap/wlan1+
ROUTE_IF="${ROUTE_IF:-}"                         # kosong = auto-detect dari ip route get VPS_IP
COMMENT="${COMMENT:-mlbb-local-server}"          # penanda aturan milik script ini
ENABLE_HOTSPOT="${ENABLE_HOTSPOT:-1}"            # 1 = klien hotspot ikut diarahkan
FORWARD_ACCEPT="${FORWARD_ACCEPT:-0}"            # 1 = tambah ACCEPT FORWARD ap0 -> uplink
# =================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTCMD="python3 ${SCRIPT_DIR}/rootcmd.py"

if ! command -v adb >/dev/null 2>&1; then
  echo "[!] adb tidak ditemukan" >&2
  exit 1
fi
if ! python3 -c 'import frida' >/dev/null 2>&1; then
  echo "[!] modul python frida tidak ditemukan" >&2
  exit 1
fi
if [ -z "${VPS_IP}" ]; then
  echo "[!] VPS_IP kosong. Isi di blok KONFIGURASI atau lewat env." >&2
  exit 2
fi

subst() {
  local s="$1"
  s="${s//__VPS_IP__/${VPS_IP}}"
  s="${s//__TCP_PORTS__/${TCP_PORTS}}"
  s="${s//__UDP_PORTS__/${UDP_PORTS}}"
  s="${s//__AP_IF__/${AP_IF}}"
  s="${s//__ROUTE_IF__/${ROUTE_IF}}"
  s="${s//__COMMENT__/${COMMENT}}"
  s="${s//__ENABLE_HOTSPOT__/${ENABLE_HOTSPOT}}"
  s="${s//__FORWARD_ACCEPT__/${FORWARD_ACCEPT}}"
  printf '%s' "$s"
}

FLUSH_CMD="$(cat <<'EOS'
# Bersihkan semua aturan lama milik script ini (nat + filter).
for t in OUTPUT PREROUTING POSTROUTING; do
  while iptables -t nat -S "$t" 2>/dev/null | grep -q __COMMENT__; do
    r=$(iptables -t nat -S "$t" | grep __COMMENT__ | head -n1)
    r=${r#-A }
    iptables -t nat -D $r
  done
done
while iptables -S 2>/dev/null | grep -q __COMMENT__; do
  r=$(iptables -S | grep __COMMENT__ | head -n1)
  r=${r#-A }
  iptables -D $r
done
EOS
)"

APPLY_CMD="$(cat <<'EOS'
VPS_IP="__VPS_IP__"
TCP_PORTS="__TCP_PORTS__"
UDP_PORTS="__UDP_PORTS__"
AP_IF="__AP_IF__"
ROUTE_IF="__ROUTE_IF__"
ENABLE_HOTSPOT="__ENABLE_HOTSPOT__"
FORWARD_ACCEPT="__FORWARD_ACCEPT__"

# Deteksi interface hotspot bila tidak diisi di konfigurasi.
if [ -z "$AP_IF" ]; then
  AP_IF=$(ip -o -4 addr show 2>/dev/null | awk '$2 ~ /^(ap|swlan|softap|wlan[1-9])/ {print $2; exit}')
fi

# Deteksi uplink yang dipakai untuk mencapai VPS.
if [ -z "$ROUTE_IF" ]; then
  ROUTE_IF=$(ip route get "$VPS_IP" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
fi
if [ -z "$ROUTE_IF" ]; then
  echo "[!] uplink tidak terdeteksi. Set ROUTE_IF di KONFIGURASI."
  exit 2
fi

echo "[*] VPS=$VPS_IP ap=${AP_IF:-none} uplink=$ROUTE_IF"

# Bersihkan aturan lama.
for t in OUTPUT PREROUTING POSTROUTING; do
  while iptables -t nat -S "$t" 2>/dev/null | grep -q __COMMENT__; do
    r=$(iptables -t nat -S "$t" | grep __COMMENT__ | head -n1)
    r=${r#-A }
    iptables -t nat -D $r
  done
done
while iptables -S 2>/dev/null | grep -q __COMMENT__; do
  r=$(iptables -S | grep __COMMENT__ | head -n1)
  r=${r#-A }
  iptables -D $r
done

# Game yang berjalan di HP ini sendiri.
for p in $TCP_PORTS; do
  iptables -t nat -A OUTPUT -p tcp --dport $p -j DNAT --to-destination $VPS_IP:$p -m comment --comment __COMMENT__
done
for p in $UDP_PORTS; do
  iptables -t nat -A OUTPUT -p udp --dport $p -j DNAT --to-destination $VPS_IP:$p -m comment --comment __COMMENT__
done

# Klien yang masuk lewat hotspot HP.
if [ "$ENABLE_HOTSPOT" = "1" ] && [ -n "$AP_IF" ]; then
  for p in $TCP_PORTS; do
    iptables -t nat -A PREROUTING -i $AP_IF -p tcp --dport $p -j DNAT --to-destination $VPS_IP:$p -m comment --comment __COMMENT__
  done
  for p in $UDP_PORTS; do
    iptables -t nat -A PREROUTING -i $AP_IF -p udp --dport $p -j DNAT --to-destination $VPS_IP:$p -m comment --comment __COMMENT__
  done
  for p in $TCP_PORTS; do
    iptables -t nat -A POSTROUTING -o $ROUTE_IF -p tcp -d $VPS_IP --dport $p -j MASQUERADE -m comment --comment __COMMENT__
  done
  for p in $UDP_PORTS; do
    iptables -t nat -A POSTROUTING -o $ROUTE_IF -p udp -d $VPS_IP --dport $p -j MASQUERADE -m comment --comment __COMMENT__
  done
  if [ "$FORWARD_ACCEPT" = "1" ]; then
    iptables -I FORWARD 1 -i $AP_IF -o $ROUTE_IF -j ACCEPT -m comment --comment __COMMENT__
  fi
else
  echo "[i] hotspot tidak dipasang (ENABLE_HOTSPOT=$ENABLE_HOTSPOT, ap=${AP_IF:-none})"
fi

echo "[+] aturan terpasang:"
iptables -t nat -S | grep __COMMENT__
EOS
)"

STATUS_CMD="$(cat <<'EOS'
echo "== route ke VPS =="
ip route get __VPS_IP__ 2>/dev/null || true
echo "== iptables nat =="
iptables -t nat -S 2>/dev/null | grep __COMMENT__ || echo "(tidak ada)"
echo "== iptables filter =="
iptables -S 2>/dev/null | grep __COMMENT__ || echo "(tidak ada)"
EOS
)"

case "${1:-apply}" in
  apply)
    # Jangan biarkan adb reverse mengalahkan DNAT ke VPS.
    for p in ${TCP_PORTS}; do
      adb reverse --remove "tcp:${p}" >/dev/null 2>&1 || true
    done
    echo "[*] Memasang aturan VPS di device (root)..."
    $ROOTCMD "$(subst "$APPLY_CMD")"
    ;;
  status)
    $ROOTCMD "$(subst "$STATUS_CMD")"
    ;;
  off)
    echo "[*] Menghapus aturan milik script ini..."
    $ROOTCMD "$(subst "$FLUSH_CMD")"
    echo "[+] selesai"
    ;;
  *)
    echo "pemakaian: $0 [apply|status|off]" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
#
# pc-hotspot.sh — jadikan PC ini sebagai hotspot (AP) dan arahkan traffic game
# ke server lokal (replay/emulate).
#
# PRASYARIT (wajib; harus dijalankan dengan root di PC):
#   Arch/CachyOS : sudo pacman -S hostapd dnsmasq iptables
#   Debian/Ubuntu: sudo apt install hostapd dnsmasq iptables
#
# Pemakaian:
#   sudo ./tools/pc-hotspot.sh on       # hotspot + redirect ke server lokal
#   sudo ./tools/pc-hotspot.sh status  # cek status
#   sudo ./tools/pc-hotspot.sh off     # lepas semua
#
# Env opsional:
#   PC_HOTSPOT_SSID     default FTRHOST-PC
#   PC_HOTSPOT_PASS     default frt12345
#   PC_HOTSPOT_CHANNEL  default 6
#   PC_HOTSPOT_IP       default 192.168.210.20
#   PC_HOTSPOT_NETMASK  default 24
#   PC_HOTSPOT_RANGE    default 192.168.210.50,192.168.210.150

set -euo pipefail

WLAN="${WLAN:-wlan0}"
SSID="${PC_HOTSPOT_SSID:-FTRHOST-PC}"
CHANNEL="${PC_HOTSPOT_CHANNEL:-6}"
PASS="${PC_HOTSPOT_PASS:-frt12345}"
PC_IP="${PC_HOTSPOT_IP:-192.168.210.20}"
NETMASK="${PC_HOTSPOT_NETMASK:-24}"
DHCP_RANGE="${PC_HOTSPOT_RANGE:-192.168.210.50,192.168.210.150}"
HOSTAPD_CONF="/tmp/opencode/hostapd-pc.conf"
HOSTAPD_PID="/tmp/opencode/hostapd-pc.pid"
DNSMASQ_PID="/tmp/opencode/dnsmasq-pc.pid"
COMMENT="mlbb-pc-hotspot"
SERVER_PORTS="30021 30071 30101 10003"

write_hostapd_conf() {
  cat > "$HOSTAPD_CONF" <<EOF
interface=${WLAN}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=${PASS}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
}

start() {
  write_hostapd_conf
  echo "[*] hostapd conf -> $HOSTAPD_CONF"
  echo "[*] matikan wifi managed lalu set mode AP"
  nmcli radio wifi off >/dev/null 2>&1 || true
  ip link set dev "$WLAN" down 2>/dev/null || true
  iw dev "$WLAN" set type ap
  ip link set dev "$WLAN" up
  ip addr flush dev "$WLAN" 2>/dev/null || true
  ip addr add "${PC_IP}/${NETMASK}" dev "$WLAN"
  hostapd -B "$HOSTAPD_CONF"
  echo $! > "$HOSTAPD_PID"
  dnsmasq --interface="$WLAN" --bind-interfaces \
    --dhcp-range="$DHCP_RANGE" \
    --dhcp-option=3,"$PC_IP" \
    --address=/login.ml.youngjoygame.com/"$PC_IP" \
    --pid-file="$DNSMASQ_PID"
  for p in $SERVER_PORTS; do
    iptables -t nat -A PREROUTING -i "$WLAN" -p tcp -m comment --comment "$COMMENT" -dport "$p" -j DNAT --to-destination "${PC_IP}:${p}"
    iptables -t nat -A POSTROUTING -o "$WLAN" -s "${PC_IP%.*}.0/24" -p tcp -m comment --comment "$COMMENT" -d "$PC_IP" -j MASQUERADE
  done
  iptables -A FORWARD -i "$WLAN" -j ACCEPT
  iptables -A FORWARD -m conntrack -ctstate ESTABLISHED,RELATED -j ACCEPT
  echo "[✓] PC hotspot aktif: SSID=$SSID IP=$PC_IP"
}

stop() {
  if [ -f "$HOSTAPD_PID" ]; then kill "$(cat "$HOSTAPD_PID")" 2>/dev/null || true; fi
  if [ -f "$DNSMASQ_PID" ]; then kill "$(cat "$DNSMASQ_PID")" 2>/dev/null || true; fi
  for p in $SERVER_PORTS; do
    iptables -t nat -D POSTROUTING -o "$WLAN" -s "${PC_IP%.*}.0/24" -p tcp -m comment --comment "$COMMENT" -d "$PC_IP" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$WLAN" -p tcp -m comment --comment "$COMMENT" -dport "$p" -j DNAT --to-destination "${PC_IP}:${p}" 2>/dev/null || true
  done
  iptables -D FORWARD -i "$WLAN" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -m conntrack -ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  echo "[✓] PC hotspot dinonaktifkan"
}

status() {
  if [ -f "$HOSTAPD_PID" ] && kill -0 "$(cat "$HOSTAPD_PID")" 2>/dev/null; then
    echo "[✓] hostapd berjalan (pid $(cat "$HOSTAPD_PID"))"
  else
    echo "[!] hostapd tidak berjalan"
  fi
  if [ -f "$DNSMASQ_PID" ] && kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null; then
    echo "[✓] dnsmasq berjalan (pid $(cat "$DNSMASQ_PID"))"
  else
    echo "[!] dnsmasq tidak berjalan"
  fi
  N="$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c "$COMMENT" || true)"
  echo "iptables PREROUTING rules dengan komentar $COMMENT: ${N:-0}"
}

case "${1:-}" in
  on)   start ;;
  off)  stop ;;
  status) status ;;
  *)
    echo "pemakaian: $0 on|off|status" >&2
    exit 2
    ;;
esac

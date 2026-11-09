# Topologi WiFi + Hotspot HP Root (yang terbukti)

Dokumen ini mencatat topologi yang **terbukti berhasil** pada 2026-11-09 untuk
mengarahkan HP non-root ke server lokal, tanpa memasang iptables di HP tersebut.

## 1. Ringkasan topologi

```text
HP lain (non-root) 192.168.21.x
        │  WiFi: FTRHOST
        ▼
HP root (gateway hotspot)  ap0 = 192.168.21.153
        │  wlan0 = 192.168.18.162
        ▼
WiFi rumah "Brajan Atas - 5G"  192.168.18.0/24
        │
        ▼
PC/laptop  wlan0 = 192.168.18.163   ← server lokal
```

Peran masing-masing:

| Perangkat | Peran | IP pada uji |
|---|---|---|
| PC/laptop | menjalankan `server/index.js` | `192.168.18.163` (WiFi rumah) |
| HP root | gateway hotspot + pemasang DNAT | `wlan0 192.168.18.162`, `ap0 192.168.21.153` |
| HP lain | klien hotspot, tanpa root | `192.168.21.x` (DHCP dari HP root) |

> IP di atas adalah hasil uji. Bila IP berubah, ganti di semua perintah
> (`SERVER_IP`, argumen `redirect.sh`, dan target DNAT).

## 2. Kenapa harus topologi ini?

### 2.1 Hotspot Android itu *routed*, bukan *bridge*

Android menjalankan hotspot sebagai gateway routed. Klien hotspot bisa bicara ke
gateway (HP), tetapi **tidak bisa bicara langsung ke klien lain**. Ini bukan bug,
memang desainnya.

Bukti saat uji:

```text
ping 192.168.21.108 dari PC  → Destination Host Unreachable
ip neigh 192.168.21.108      → FAILED
```

Jadi PC yang ikut hotspot tidak bisa diakses langsung oleh HP lain, walaupun
keduanya sama-sama terhubung ke `FTRHOST`.

### 2.2 HP non-root tidak bisa memasang iptables

HP non-root tidak punya cara untuk membelokkan traffic game-nya sendiri. Game
menghubungi IP server resmi, bukan IP PC. Satu-satunya titik yang bisa kita
kendalikan adalah **gateway hotspot** (HP root), karena di situ DNAT bisa
dipasang.

### 2.3 Target DNAT harus IP PC di WiFi *upstream*

HP root dan PC sama-sama tersambung ke WiFi rumah `192.168.18.0/24`. Karena itu:

- DNAT di HP root diarahkan ke `192.168.18.163` (IP PC di WiFi rumah), **bukan**
  ke IP PC di hotspot (PC memang tidak ikut hotspot).
- HP root mengirim paket itu lewat `wlan0` (WiFi rumah), bukan `ap0`.
- Router WiFi rumah meneruskan paket ke PC `192.168.18.163`.
- `MASQUERADE` mengubah source menjadi IP `wlan0` HP root (`192.168.18.162`),
  sehingga balasan PC kembali ke HP root, lalu diteruskan ke klien hotspot.

Kalau target DNAT memakai IP di subnet hotspot (mis. `192.168.21.209`), hasilnya
tidak reliabel: Android policy routing bisa mengirim paket lewat `wlan0`
(default upstream), dan kalaupun route `ap0` ditambahkan, koneksi zone menjadi
client-to-client yang diblokir oleh hotspot Android.

### 2.4 `SERVER_IP` harus sama dengan IP PC di WiFi rumah

Auth server mengirim `sConnServer` ke game. Nilai itu diambil dari `SERVER_IP`.
Kalau diisi `192.168.18.163`, koneksi zone juga akan melewati HP root → WiFi
rumah → PC. Kalau diisi IP lain (mis. IP hotspot PC), game akan mencoba konek
langsung ke IP yang tidak bisa dijangkau dari klien hotspot.

## 3. Prasyarat

- PC dan HP root tersambung ke **WiFi rumah yang sama**.
- HP root bisa menjalankan `iptables` (root/Frida seperti `tools/rootcmd.py`).
- Hotspot HP root aktif, SSID `FTRHOST`, password `ffffffff`
  (lihat `/data/vendor/wifi/hostapd/hostapd_ap0.conf`).
- `adb` ke HP root dan `frida-server` di port `2626` berjalan.
- Server PC mendengarkan `0.0.0.0` pada port `30021`, `30071`, `30101`, `10003`.
- IP PC sebaiknya dijadikan DHCP reservation agar tidak berubah.

## 4. Langkah lengkap

### 4.1 Di PC/laptop

1. Sambungkan PC ke WiFi rumah, lalu cek IP:

   ```bash
   nmcli connection up "Brajan Atas - 5G"
   ip -4 addr show wlan0
   ```

   Contoh hasil: `192.168.18.163/24`.

2. Jalankan server dengan `SERVER_IP` = IP PC di WiFi rumah:

   ```bash
   SERVER_IP=192.168.18.163 MODE=emulate DIAMOND=9999999 LEVEL=999 \
     node server/index.js
   ```

3. Pastikan `adb` dan Frida siap:

   ```bash
   adb devices
   # bila ada lebih dari satu transport (mDNS + IP), pilih satu:
   export ANDROID_SERIAL=192.168.18.162:43783
   adb -s "$ANDROID_SERIAL" forward tcp:2626 tcp:2626
   ```

4. Pasang DNAT di HP root:

   ```bash
   ./tools/redirect.sh wifi 192.168.18.163
   ```

   Atau, bila hotspot sudah aktif:

   ```bash
   ./tools/hotspot.sh on
   ```

   `hotspot.sh on` akan mendeteksi IP PC otomatis dan memasang aturan untuk
   klien hotspot.

### 4.2 Di HP root

1. Nyalakan hotspot `FTRHOST` dari Settings (Personal Hotspot), atau lewat root:

   ```bash
   python3 tools/rootcmd.py "cmd wifi start-softap FTRHOST wpa2 ffffffff"
   ```

   Catatan: `cmd wifi start-softap` **gagal** bila dijalankan sebagai shell biasa
   (`SecurityException: MAINLINE_NETWORK_STACK`). Harus lewat root, misalnya
   `tools/rootcmd.py`, atau nyalakan manual dari Settings. `rootcmd.py` kadang
   melaporkan timeout 20 detik meskipun hotspot tetap berhasil dinyalakan; cek
   `ip -o -4 addr show ap0` untuk memastikan.

2. Cek hotspot dan upstream:

   ```bash
   adb shell 'ip -o -4 addr show ap0'
   adb shell 'ip -o -4 addr show wlan0'
   adb shell 'ip route get 192.168.18.163'
   ```

   Hasil yang diharapkan:

   - `ap0` = `192.168.21.153/24`
   - `wlan0` = `192.168.18.162/24`
   - route ke `192.168.18.163` lewat `wlan0`

### 4.3 Di HP lain (non-root)

1. Sambungkan ke WiFi `FTRHOST` (password `ffffffff`).
2. Pastikan mendapat IP `192.168.21.x` dari DHCP hotspot.
3. Buka game. Traffic port `30021/30071/30101/10003` akan dibelokkan oleh HP
   root ke PC `192.168.18.163`.

## 5. Aturan yang dipasang

`tools/redirect.sh wifi 192.168.18.163` memasang:

```text
# Untuk HP root sendiri
iptables -t nat -A OUTPUT -p tcp --dport <port> \
  -j DNAT --to-destination 192.168.18.163:<port>

# Untuk semua klien hotspot (kecuali traffic dari PC)
iptables -t nat -A PREROUTING ! -s 192.168.18.163 -i ap0 -p tcp --dport <port> \
  -j DNAT --to-destination 192.168.18.163:<port>

# Balasan PC kembali lewat HP root
iptables -t nat -A POSTROUTING -o wlan0 -p tcp -d 192.168.18.163 --dport <port> \
  -j MASQUERADE
```

Port yang dipakai: `30021`, `30071`, `30101`, `10003`.

## 6. Verifikasi

Di PC:

```bash
ss -tnp | grep -E ':(30021|30071|30101|10003)'
```

Di HP root:

```bash
adb shell 'ip neigh show dev ap0'
```

Di HP lain:

- Game harus menampilkan loading/lobby dari server lokal.
- Bila perlu, cek logcat:

  ```bash
  adb logcat | grep -iE 'mobile\.legends|socket|connect|timeout'
  ```

## 7. Kenapa PC jangan ikut hotspot

Topologi yang **gagal**:

```text
PC ikut FTRHOST → IP PC 192.168.21.209
DNAT target = 192.168.21.209
```

Masalahnya:

1. Android policy routing mengirim traffic `iif ap0` ke tabel `wlan0`
   (default via WiFi upstream), bukan ke `ap0`. Paket DNAT bisa keluar ke
   router rumah dan tidak pernah sampai ke PC.
2. Walaupun route `192.168.21.0/24 dev ap0` ditambahkan ke tabel `wlan0`,
   koneksi **zone** dari klien ke `192.168.21.209:30101` tetap merupakan
   client-to-client, yang diblokir hotspot Android.

Karena itu, untuk klien hotspot, target harus IP PC di **WiFi upstream**
(`192.168.18.163`), bukan IP PC di subnet hotspot.

## 8. Troubleshooting

| Gejala | Penyebab | Tindakan |
|---|---|---|
| HP lain masih memakai server resmi | HP lain masih di WiFi rumah, bukan `FTRHOST` | sambungkan ke `FTRHOST` |
| HP lain dapat IP `192.168.18.x` | masih terhubung ke WiFi rumah | lupakan WiFi rumah sementara / matikan auto-connect |
| Game stuck di login | `SERVER_IP` bukan IP PC di WiFi rumah | restart server dengan `SERVER_IP=192.168.18.163` |
| Game tidak bisa konek ke PC | HP root tidak tersambung ke WiFi rumah | sambungkan `wlan0` ke `Brajan Atas - 5G` |
| DNAT tidak aktif setelah reboot | aturan iptables hilang | jalankan ulang `./tools/redirect.sh wifi 192.168.18.163` |
| IP PC berubah | DHCP memberi alamat baru | jalankan ulang redirect dan restart server dengan IP baru |
| `cmd wifi start-softap` SecurityException | dijalankan sebagai shell, bukan root | pakai `tools/rootcmd.py` atau nyalakan dari Settings |
| Klien hotspot tidak dapat IP | tethering belum aktif | cek `dumpsys tethering`, pastikan `ap0 - TetheredState` |

## 9. Bukti uji 2026-11-09

- PC: `192.168.18.163`, server `MODE=emulate DIAMOND=9999999 LEVEL=999`.
- HP root: `192.168.18.162`, hotspot `FTRHOST`, `ap0 192.168.21.153`.
- Game di HP root berhasil terhubung ke server lokal (port `30021`/`30101`
  terlihat `ESTAB` di `ss`).
- HP lain harus join `FTRHOST`; bila masih di WiFi rumah, tidak ada aturan
  redirect karena HP tersebut non-root.

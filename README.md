# MLBB Private Server — Relay → Replay → Emulate

Server lokal untuk menguji alur login Mobile Legends: Bang Bang **tanpa** mengubah
paket yang menuju server resmi. Fokus proyek: merekam lalu memutar ulang respons
server resmi di PC sendiri, dengan opsi menimpa nilai `iDiamond` menjadi **2626**
dan `iLevel` menjadi **28** pada mode `emulate`.

> ⚠️ Hanya untuk perangkat dan akun uji milik sendiri. Lihat `PRD.md` §2 (N1–N6)
> dan `CLAUDE.md`. Jangan pakai untuk penggunaan publik/komersial.

---

## 1. Arsitektur singkat

```
Game di device
  │  (iptables di device, bukan mengubah byte)
  ├── REDIRECT 127.0.0.1 ── adb reverse ──▶ PC (USB)
  └── DNAT <IP-PC> ──────── LAN/hotspot ──▶ PC (WiFi)
                                     │
                     MODE=relay ─────┴──▶ server resmi (passthrough byte-identik)
                     MODE=replay  ────────▶ cache captures/<sesi>/
                     MODE=emulate ────────▶ cache + override diamond/level
```

- **Relay** tidak menyentuh payload: hanya meneruskan byte dan mencatat frame.
- **Replay/emulate** menjawab dari capture lokal, tidak pernah menghubungi server
  resmi. Respons zone mengikuti aturan **opcode request + `0x100`**.
- Port klien build `2.2.29.1250.1`: auth **30021/30071**, zone **30101/10003**.
  Server mendengarkan keempatnya sekaligus (dipisah koma pada env).

---

## 2. Prasyarat

- Linux, Node.js ≥ 18 (diuji v22), Python ≥ 3.10, `adb`, `frida` (Python), `zstd`.
- Device Android dengan `frida-server` berjalan sebagai root di port `2626`.
- Game `com.mobilelegends.taptest` (build uji `2.2.29.1250.1`).
- APK/`dump.cs`/`captures/` **tidak** ikut di-commit.

---

## 3. Reproduksi

Dari direktori proyek (`/home/petwirkepo/Downloads/files`):

```bash
# 0) build agent Frida
npx frida-compile agent.js -o dist/agent.js -c

# 1) jalur device -> PC (wajib setelah reboot / cabut USB)
adb forward tcp:2626 tcp:2626
./tools/redirect.sh on          # USB/adb: 30021, 30071, 30101, 10003
# atau tanpa adb reverse (LAN/hotspot):
# ./tools/redirect.sh wifi      # IP PC dideteksi otomatis
python3 -u collector.py &       # Frida via Python (bukan MCP)

# 2) server lokal
MODE=emulate node server/index.js          # diamond+level dari state/profile.json
# atau: MODE=emulate DIAMOND=2626 LEVEL=28 node server/index.js

# 3) jalankan game
adb shell monkey -p com.mobilelegends.taptest -c android.intent.category.LAUNCHER 1

# 4) matikan pengalihan bila ingin kembali ke server resmi
./tools/redirect.sh off
```

Bila ingin **merekam** sesi resmi (Fase 1) untuk memperluas cache:

```bash
MODE=relay node relay.js
# login, buka menu (Heroes/Inventory/Preparation), lalu kembali ke emulate
```

Cache replay memakai **sesi capture terbaru** secara otomatis, jadi cukup restart
server setelah capture baru.

### 3.1 Mode WiFi (tanpa `adb reverse`)

Server sudah mendengarkan `0.0.0.0`, jadi device lain di jaringan yang sama bisa
langsung diarahkan ke PC:

```bash
./tools/redirect.sh wifi                 # IP PC dideteksi otomatis
./tools/redirect.sh wifi 192.168.18.163  # atau sebutkan IP PC di WiFi rumah
./tools/redirect.sh status               # cek DNAT + adb reverse kosong
./tools/redirect.sh off                  # kembali ke server resmi
```

Bila device dijadikan hotspot, cukup pakai helper:

```bash
./tools/hotspot.sh on        # cek hotspot + pasang DNAT untuk device & klien
./tools/hotspot.sh clients   # daftar perangkat yang tersambung
./tools/hotspot.sh status    # SSID, IP hotspot, klien, aturan
./tools/hotspot.sh off       # lepas semua pengalihan
```

Contoh: hotspot device bernama `FTRHOST`; PC tersambung ke **WiFi rumah yang
sama** dengan device (bukan sebagai klien hotspot). Semua perangkat yang join
`FTRHOST` diarahkan ke server lokal PC tanpa root di perangkat klien.

> **Topologi yang terbukti (2026-11-09):** PC dan HP root sama-sama tersambung
> ke WiFi rumah `Brajan Atas - 5G` (PC `192.168.18.163`, HP root
> `192.168.18.162`). HP root menyalakan hotspot `FTRHOST`; HP lain yang
> **non-root harus join `FTRHOST`**, bukan WiFi rumah. Server dijalankan dengan
> `SERVER_IP=192.168.18.163` dan DNAT dipasang lewat
> `./tools/redirect.sh wifi 192.168.18.163`. Alasan lengkap, diagram, dan
> troubleshooting: [`docs/TOPOLOGI-WIFI-HOTSPOT.md`](docs/TOPOLOGI-WIFI-HOTSPOT.md).

Agar aturan otomatis dipasang ulang setelah Android membersihkan NAT saat
jaringan berubah:

```bash
nohup ./tools/redirect-watch.sh >/tmp/opencode/redirect-watch.log 2>&1 &
```

Yang dilakukan mode `wifi`:

- `iptables -t nat OUTPUT -j DNAT --to-destination <IP-PC>:<port>` untuk device
  yang menjalankan skrip (trafik game diubah tujuannya, payload tidak disentuh).
- Bila device sedang menjadi hotspot (mis. interface `ap0`), ditambahkan
  `PREROUTING` DNAT + `POSTROUTING` MASQUERADE, sehingga **perangkat lain yang
  tersambung ke hotspot itu otomatis memakai server lokal** tanpa root di
  perangkat klien.
- Target `<IP-PC>` harus IP PC yang bisa dijangkau lewat interface **upstream**
  device (mis. IP PC di WiFi rumah), **bukan** IP PC di subnet hotspot. Bila PC
  ikut hotspot, koneksi zone menjadi client-to-client dan diblokir oleh hotspot
  Android.
- `adb reverse` dilepas, jadi koneksi murni lewat LAN/hotspot.

Syarat: PC dan device saling terjangkau, firewall PC mengizinkan port
`30021/30071/30101/10003`, dan device yang menjalankan skrip harus root. Aturan
bertahan sampai reboot; setelah reboot atau IP PC berubah, jalankan ulang
`./tools/redirect.sh wifi`.

### 3.2 Alternatif: PC sebagai hotspot (tanpa HP)

Bisa juga **PC sendiri** yang dipasang sebagai hotspot, sehingga semua perangkat
(HJ) cukup join SSID-nya lalu otomatis dialihkan ke server lokal oleh PC. Ini
alternatif untuk HP non-root yang tidak mau atau tidak bisa join hotspot HP root.
Pendukung hardware: adapter `wlan0` PC mendukung mode `AP` (`iw list` →
`* AP`, `* AP/VLAN`).

```bash
sudo ./tools/pc-hotspot.sh on       # hostapd + dnsmasq(DHCP/DNS) + iptables DNAT
sudo ./tools/pc-hotspot.sh status
sudo ./tools/pc-hotspot.sh off
```

Catatan: `tools/pc-hotspot.sh` memerlukan hostapd + dnsmasq + iptables yang
terpasang di PC (root), mis. `sudo pacman -S hostapd dnsmasq iptables`
(Arch/CachyOS) atau `sudo apt install hostapd dnsmasq iptables`
(Debian/Ubuntu). Saat PC dipasang sebagai AP, PC harus melepas dulu koneksi WiFi
managed (`Brajan Atas - 5G`) supaya `wlan0` bisa berubah ke mode AP.

---

## 4. Pengujian

```bash
node test-sdp.js                                        # vektor bawaan (7/7)
node test-sdp.js captures/<sesi>/*.bin                  # round-trip semua frame
node test-relay.js                                      # relay + parser (9/9)
node tools/verify-diamond.js                            # diamond+level offline
node tools/verify-diamond.js 2626 28                    # eksplisit
```

Catatan: file `*-unknown-*` adalah byte non-protokol (mis. laporan teks login) yang
tidak bisa di-round-trip; `test-sdp.js` melewatinya secara eksplisit.

---

## 5. Format yang perlu diingat

- Frame biasa: `[total u32BE][opcode u32BE][seq u8][…header…][body SDP]`.
- Amplop zstd/probe: `[10 00][total u16BE][zstd payload]`, dengan
  `payload = [opcode u32][seq u8][byte tambahan][0x46][varint(bodyLen-1)][body]`.
- Header SDP memakai tag nibble; tag ≥ 15 memakai penanda `0xf` + varint.
- `0x7000a14e` = laporan telemetri `client_loginstepdata` (fire-and-forget,
  **tidak dibalas** server resmi).
- `0x7000f64e` = `Cmd_Role_Init_SC`, field `iLevel` = tag **3**, `iDiamond` =
  tag **11**. Nilai diamond 0 tidak diserialisasi, jadi override harus
  **menyisipkan** tag pada urutan benar.
- `0x7000a04f` = `Cmd_Role_GetInfo_SC` (balasan `0x70009f4f`) juga membawa
  `iLevel` di tag **3**; dipatch agar level tidak kembali ke nilai capture.

---

## 6. Pengaturan lokal

`state/profile.json`:

```json
{ "diamond": 2626, "level": 28 }
```

- Env `DIAMOND` / `LEVEL` menimpa nilai profil.
- Override hanya aktif di `MODE=emulate`; `MODE=relay` menolak override.
- Waktu server (`Cmd_Net_ServerTime_SC`, tag 0) selalu diisi waktu sekarang.
- Request yang belum punya cache/handler disimpan ke `unhandled/` (`.bin` + `.json`),
  tidak dibalas "sukses" palsu.

---

## 7. Opcode yang belum ditangani

Daftar dari capture emas `captures/2026-11-07-08-40-31` dan sesi lanjutan
(tidak punya respons `+0x100`). Semuanya dicatat ke `unhandled/` saat muncul:

```
0x7000a34f  0x7000ac58  0x7000c5d5  0x7000cd65  0x7000db51
0x7000efb8  0x7000f3f8  0x7000fbb8  0x7000a14f  0x7000ea8b
0x7000d551  0x7000f14f  0x7000cf53  0x7000fa55
```

Opcode tersebut tidak menghalangi login → lobby (diamond 2626, level 28). Untuk
melengkapinya, rekam lewat `MODE=relay` saat memicu fitur terkait, lalu jalankan
ulang:

```bash
node tools/match-opcodes.js
node tools/build-schema.js
```

---

## 8. Troubleshooting

| Gejala | Penyebab umum | Tindakan |
|---|---|---|
| Game memakai server resmi | `adb reverse` hilang setelah reboot/cabut USB | jalankan `./tools/redirect.sh on` atau `wifi` |
| Ingin main lewat WiFi/hotspot | belum ada DNAT ke PC | `./tools/redirect.sh wifi` (root di device) |
| Perangkat lain di hotspot tidak masuk server lokal | aturan `PREROUTING` belum terpasang | cek `./tools/redirect.sh status`, pastikan interface `ap0` terdeteksi |
| HP non-root di WiFi rumah tidak masuk server lokal | tidak ada iptables/router DNAT | sambungkan HP ke hotspot HP root, atau pasang port forwarding di router |
| PC ikut hotspot, klien tidak bisa masuk | target DNAT berada di subnet hotspot (client-to-client) | pindahkan PC ke WiFi upstream, pakai IP PC di WiFi rumah |
| Game stuck di zone setelah auth | `SERVER_IP` bukan IP PC di WiFi upstream | restart server dengan `SERVER_IP=<IP-PC-WiFi-rumah>` |
| IP PC berubah setelah reconnect | DHCP hotspot memberi alamat baru | jalankan ulang `./tools/redirect.sh wifi` |
| Relay hanya melihat auth | port zone klien berbeda | pastikan `ZONE_PORT=30101,10003` |
| `frida.ServerNotRunningError` | `adb forward tcp:2626` belum ada | `adb forward tcp:2626 tcp:2626` |
| Attach Frida timeout saat cold start | Unity belum siap | biarkan `collector.py` retry, atau attach setelah game stabil |
| Game force close / low memory | RAM device penuh | `am force-stop`, `am kill-all`, lalu buka ulang |
| Lobby kosong / fitur menggantung | opcode belum ada di cache | lihat `unhandled/`, rekam via relay |
| Angka diamond lain di toko | respons lain membawa saldo | tambahkan patch dari state yang sama (FR-5.3) |

Log runtime yang dipakai saat pengembangan: `/tmp/opencode/server.log`,
`/tmp/opencode/relay.log`, `/tmp/opencode/collector.log`.

---

## 9. Status

Lihat `PROGRESS.md` dan `docs/LANJUTKAN.md`. Ringkas: Fase 1–5 berjalan; login →
lobby dari server lokal, diamond **2626**, level **28**, stabil (heartbeat
`0x7000954e` dibalas dari cache).

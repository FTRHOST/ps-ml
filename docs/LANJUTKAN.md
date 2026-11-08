# Lanjutkan — MLBB Private Server

Catatan untuk melanjutkan pekerjaan setelah handoff `PROGRESS.md`. Fokus dokumen:
di mana posisi, apa yang sudah terbukti hari ini, dan langkah berikutnya.

---

## 1. Status saat ini

| Area | Status | Catatan |
|---|---|---|
| Fase 0 — SDP | ✅ | `node test-sdp.js` 7/7 |
| Fase 1 — Relay/Capture | ✅ | `1136 lulus / 0 gagal` pada `captures/2026-11-07-08-40-31` |
| Fase 2 — Opcode→class + skema | 🟡 | `opcodes.jsonl` 35, `schema/schema.json` 35 (cakupan class 35/35); cache replay 146 opcode |
| Fase 3 — Replay | ✅ | login bersih → lobby dari server lokal |
| Fase 4 — Emulate | ✅ | guard mode + patch body SDP |
| Fase 5 — Diamond 2626 + Level 28 | ✅ | lobby menampilkan diamond 2626 dan Lv. 28 |

### Pencapaian Fase 2 (2026-11-06)

- **Pendekatan:** hook `PackUtil.Unpack(Type, ReturnMsg)` → emit
  `(class_name, body_hex)` → cocokkan dengan body paket `RECV_/SEND_` →
  `opcode` = byte 0 raw → `opcodes.jsonl`.
- **Output:** `node tools/match-opcodes.js` → `mlbb_captured_tags/opcodes.jsonl`
  (32 opcode, confidence 1 untuk mayoritas, divalidasi memakai body eksplisit).
- **Skema:** `node tools/build-schema.js` → `schema/schema.json` (32 opcode → class,
  field + tag + type).

Cakupan saat ini rendah relatif ke 121 opcode unik yang pernah terlihat, karena beberapa
class hanya muncul sekali, besar, atau tidak terbaca. Ini normal; prioritas berikutnya
adalah menambah sesi capture.

---

## 2. Cara menjalankan pipeline sekarang

```bash
# dari /home/petwirkepo/Downloads/files
npx frida-compile agent.js -o dist/agent.js -c

# 1) siapkan jalur device -> PC
adb forward tcp:2626 tcp:2626
./tools/redirect.sh on          # USB/adb: 30021, 30071, 30101, 10003
# atau tanpa adb reverse (LAN/hotspot):
# ./tools/redirect.sh wifi      # IP PC dideteksi otomatis
python3 -u collector.py &       # Frida (Python)

# 2) server lokal (tanpa server resmi)
MODE=emulate node server/index.js          # diamond+level dari state/profile.json
# atau: MODE=emulate DIAMOND=2626 LEVEL=28 node server/index.js
adb shell monkey -p com.mobilelegends.taptest -c android.intent.category.LAUNCHER 1

# 3) gate
node test-sdp.js
node test-sdp.js captures/2026-11-07-08-40-31/*.bin
node tools/verify-diamond.js 2626 28
node test-relay.js

# 4) bila perlu capture resmi lagi (relay -> official)
./tools/redirect.sh on
MODE=relay node relay.js
```

> **Penting:** `./tools/redirect.sh on` wajib setelah setiap reboot / cabut USB,
> karena `adb reverse` hilang. Tanpa itu, game akan memakai server resmi.

---

## 3. Jebakan terbaru (per 2026-11-06)

1. **`isValidPtr` (frida-il2cpp-bridge) salah.** Fungsi itu menolak pointer valid di
   build Android arm64 (termasuk heap yang ber-tag `0xb4...`). Semua hook yang memakai
   `isValidPtr(p) && isValidPtr(args[0])` diam-diam lewat tanpa emit. Solusi: pakai
   `!ptr.isNull()` + try/catch.
2. **`DecodeMsgBody` retval tidak valid** (selalu `0xd02d9cb0`). Jadi mapping
   `opcode ↔ messageid` hanya bisa lewat `Unpack` args. Untuk Fase 3, cukup pakai
   `sdp_bodies.jsonl` + `opcodes.jsonl`.
3. **Body wire = body Unpack + byte `0x80`** penutup → strip sebelum cocok.
4. **`RspProto/ReqProto.visit` + `bytesToSdp` tidak terpanggil** pada build ini
   (mungkin di-inline) → jangan andalkan.
5. `dump.cs` bergeser setelah field ke-55 → gunakan tag dari `tags.jsonl` /
   toleransi geser.
6. Game sering mati (lowmemorykiller) → lakukan force-stop → collector → launch
   berurutan, dan `adb shell pm trim-caches`.

---

## 4. Langkah lanjutan

1. **Stabilitas.** Biarkan game di lobby ≥10 menit; pantau `cache miss` di log server.
   Opcode yang masih miss tercatat di `PROGRESS.md` §9.
2. **Perluas cache.** Jalankan `MODE=relay node relay.js`, buka menu Heroes/Inventory/
   Preparation, lalu kembali ke `MODE=emulate`. Cache memakai sesi **terbaru** otomatis.
3. **Cakupan skema.** `node tools/match-opcodes.js` + `node tools/build-schema.js`
   setelah capture baru; target ≥95% opcode punya class.
4. **Emulate bertahap.** Opcode yang butuh nilai dinamis (server time, session key,
   daftar hero) sebaiknya dibangun dari state, bukan replay mentah.
5. **Diamond & level.** Nilai ada di `state/profile.json` (`diamond`, `level`), bisa
   ditimpa `DIAMOND=` / `LEVEL=`. Override menyentuh `Cmd_Role_Init_SC` tag 11
   (diamond) dan tag 3 (level), serta `Cmd_Role_GetInfo_SC` tag 3 (level); jangan
   aktifkan di relay.

### Ringkasan teknis yang wajib diingat

- Port klien build ini: auth **30021/30071**, zone **10003/30101**.
- Frame besar: `[10 00][total u16][zstd([opcode][seq][..][0x46][varint len][body])]`.
- `0x7000a14e` = telemetri teks login; **tidak dibalas** (jangan tunggu cache).
- Respon zone = opcode request **+0x100**.
- `Number(hex, 16)` itu bug (radix diabaikan) → selalu `parseInt(hex, 16)`.

---

## 5. Status terkini (2026-11-06, sesi ini)

1. **Fase 2 — mapping opcode → class: SOLVED.**
   - Cara: hook `Unpack` → emit `(class_name, body_hex)` → `tools/match-opcodes.js` → vote
     → `opcodes.jsonl` (32 opcode, confidence 1).
   - `tools/build-schema.js` → `schema/schema.json` (32 opcode → class).
2. **Fase 3 — replay/emulate: server lokal berjalan dan menerima trafik nyata.**
   - `server/index.js` (MODE=replay) + `auth-server.js` (builder) mulai berfungsi.
   - Smoke test terverifikasi: cold start → Auth_SC → GetBulletin_SC → CheckUpgrade_SC →
     Net_Connect_SC → lobby handshake ke server lokal.
   - Response di-cache dari `captures/**` per opcode (response = request + 0x100).
3. **Gate wajib:** `node test-sdp.js` (7/7) dan `node test-sdp.js captures/2026-11-04-09-27-04/*.bin`
   (7142 lulus / 0 gagal) — **seluruh hijau**.

---

## 6. Status lanjutan

1. Fase 3 lanjut: lengkapi handler lobby (Hero_GetList, Role_Init, hero data, battle) dengan
   replay dari cache, lalu uji login→lobby secara penuh.
2. Fase 3 selesai: `MODE=replay` harus membuat client bertahan ≥ 10 menit di lobby.
3. Fase 4: `MODE=emulate` dengan handler per opcode + `server/state/profile.json`.
4. Fase 5: override diamond 2626 dan level 28 (hanya `emulate`).

---

## 7. Kredensial & akun

- Akun uji: `Test-ori` (uid, level capture 6 → override **28**, coin 3243,
  diamond capture 0 → override **2626**), `GGGimang`.
- Game versi: `com.mobilelegends.taptest` v2.2.29.x; device Redmi Note 9.

---

## 8. Status final (2026-11-08)

1. **Diamond 2626 + level 28 terverifikasi di lobby.** Screenshot lobby menunjukkan
   `Test-ori Lv. 28` dan diamond `2626`. Override berjalan di `MODE=emulate`:
   - `Cmd_Role_Init_SC` (`0x7000f64e`): `iDiamond` tag 11, `iLevel` tag 3.
   - `Cmd_Role_GetInfo_SC` (`0x7000a04f`): `iLevel` tag 3 (tanpa ini level
     kembali ke 6 saat info role disegarkan).
2. **Gate hijau:** `test-sdp.js` 7/7, capture gate 1136/0, `test-relay.js` 9/9,
   `tools/verify-diamond.js 2626 28` lulus.
3. **Cache 146 opcode**, sesi terbaru menang tetapi opcode lama tetap di-merge.
4. **Push server:** setelah `0x70009f4f` → `0x7000a04f`, server mengirim
   `0x7000b04f` dari cache untuk membantu layar Preparation.
5. **Opcode belum tertangani** tercatat di `unhandled/`:
   `0x7000a34f`, `0x7000ac58`, `0x7000c5d5`, `0x7000cd65`, `0x7000db51`,
   `0x7000efb8`, `0x7000f3f8`, `0x7000fbb8`, `0x7000a14f`, `0x7000ea8b`,
   `0x7000d551`, `0x7000f14f`, `0x7000cf53`, `0x7000fa55`.
6. **Batasan diketahui:** menu Preparation masih berhenti di "Retrieving data"
   lalu kembali ke lobby; Heroes/Inventory/Shop berfungsi. Tidak ada pembelian
   yang dilakukan saat pengujian.
7. `SERVER_IP=0.0.0.0` tetap benar: device memakai REDIRECT + `adb reverse`,
   sehingga tujuan asli di `ss` masih terlihat sebagai IP resmi.
8. **Mode WiFi/hotspot berjalan.** `./tools/redirect.sh wifi` memasang DNAT ke
   IP PC (tanpa `adb reverse`). Bila device menjadi hotspot (`ap0`), aturan
   `PREROUTING` + `POSTROUTING MASQUERADE` membuat perangkat lain di hotspot
   otomatis memakai server lokal. Terverifikasi login → lobby (Lv. 28,
   diamond 2626) lewat LAN, ping ~100 ms. Helper: `./tools/hotspot.sh on`,
   `./tools/hotspot.sh status`, dan `./tools/redirect-watch.sh` untuk memasang
   ulang aturan bila dibersihkan Android.

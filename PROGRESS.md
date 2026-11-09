# PROGRESS — Handoff MLBB Private Server

> **Untuk AI agent berikutnya:** baca `CLAUDE.md` + `PRD.md` dulu, lalu berkas ini.
> Berkas ini adalah catatan keadaan nyata di lapangan (per 2026-11-08 16:50 WIB),
> termasuk hal yang **belum** berhasil. Jangan mengulang eksperimen yang sudah dicoba.

---

## 1. Aturan keras (jangan dilanggar)

1. Mode `relay` = **passthrough byte-identik**. Tidak boleh mengubah/menyuntik/menghapus byte.
2. Override diamond dan level **hanya** di mode `emulate`. Tolak bila upstream resmi aktif.
3. Jangan commit `captures/`, `state/`, `relay-captures/`, `mlbb_captured_tags/`,
   `dump.cs`, APK, session key.
4. `node test-sdp.js captures/<sesi>/*.bin` wajib 100% lulus sebelum menyentuh `sdp.js`.
5. Bahasa komentar/komunikasi: Indonesia. Identifier: Inggris. Node CommonJS.

---

## 2. Status fase

| Fase | Status | Bukti |
|---|---|---|
| 0 — Fondasi SDP | ✅ | `node test-sdp.js` 7/7 vektor bawaan |
| 1 — Relay & Capture | ✅ | `node test-sdp.js captures/2026-11-07-08-40-31/*.bin` → **1136 lulus, 0 gagal** (2567 file `-unknown-` = teks non-protokol, dilewati) |
| 2 — Skema & peta opcode | 🟡 **cukup untuk replay** | `opcodes.jsonl` 35 opcode; `schema/schema.json` 35 opcode → class (cakupan class 35/35). Cache replay kini **146 opcode**. |
| 3 — Replay | ✅ | Klien login → **lobby** penuh dari `MODE=replay`/`emulate`, tanpa koneksi ke zone resmi |
| 4 — Emulate | ✅ | `MODE=emulate` + guard mode + patch field SDP (diamond & level) |
| 5 — Diamond 2626 + Level 28 | ✅ | Lobby menampilkan diamond **2626** dan **Lv. 28** (screenshot 2026-11-08 16:47) |

---

## 2.1 Temuan kunci (2026-11-07) — ini yang membuat replay akhirnya jalan

1. **Port klien bergeser.** Build `2.2.29.1250.1` memakai
   `30021`/`30071` untuk auth dan `10003` untuk zone (`30101` lama hanya sesekali).
   REDIRECT lama (30021+30101) membuat trafik zone lolos langsung ke server resmi —
   ini sebabnya relay lama hanya melihat fase auth.
   → `relay.js` dan `server/index.js` sekarang mendengarkan **daftar port**
   (`AUTH_PORT`/`ZONE_PORT` dipisah koma), `tools/redirect.sh` mengalihkan keempatnya.
2. **Frame besar dibungkus zstd.** Format amplop:
   `[10 00][total u16BE][zstd payload]`, dengan
   `payload = [opcode u32][seq u8][byte tambahan][0x46][varint(bodyLen-1)][body]`.
   → cache replay wajib membaca `.zstd`, bukan hanya `.bin`
   (`Cmd_Role_Init_SC` justru tersimpan sebagai `.zstd`).
3. **Bug fatal `Number(hex, 16)`.** `Number("7000f64e", 16)` mengabaikan radix →
   `NaN`, sehingga **seluruh cache replay kosong** dan server selalu menjawab
   "tidak ada cache". Sudah diganti `parseInt(hex, 16)`.
4. **`0x7000a14e` bukan request berbalas.** Isinya laporan teks
   `client_loginstepdata` (fire-and-forget) yang dikirim 100+ kali; server resmi
   tidak membalas. Masuk daftar `NO_REPLY`, jadi tidak lagi dianggap cache miss.
5. **`iDiamond` sering tidak ada di body** karena nilainya 0 dan tidak
   diserialisasi. Patch harus **menyisipkan** tag 11 pada urutan tag yang benar,
   bukan hanya menimpa field yang sudah ada.
6. **Level ada di dua tempat.** `Cmd_Role_Init_SC` (`0x7000f64e`) membawa `iLevel`
   di tag 3; `Cmd_Role_GetInfo_SC` (`0x7000a04f`, balasan `0x70009f4f`) juga
   membawa `iLevel` di tag 3. Keduanya harus dipatch, kalau tidak level kembali ke
   nilai capture (6) saat klien menyegarkan info role.
7. **`test-sdp.js` vs data teks.** Kanal `30071` juga membawa laporan teks login
   (bukan SDP). Relay kini menyimpannya sebagai satu potongan `-unknown-`, dan
   `test-sdp.js` melewati berkas `-unknown-` (bukan frame).
**Bukti akhir:** dengan `MODE=emulate DIAMOND=2626 LEVEL=28 node server/index.js`,
game login bersih → lobby, header menampilkan diamond **2626** dan **Lv. 28**, dan
semua balasan berasal dari `captures/2026-11-07-09-11-06` (sesi resmi terbaru yang
punya frame role).

---

## 3. Yang sudah selesai dan terverifikasi

### 3.1 `sdp.js` (jangan rusak API-nya)
- `parseFrame` mendukung format live:
  `[len u32BE][opcode u32BE][1–3 varint][0x45|0x46][varint bodyLen-1][body]`
  plus fallback format lama (`02 00 05 00 45/46`), login `45/46`, dan compact.
- Mengembalikan `hdr` asli sehingga `buildFrame(opcode, seq, body, envelope, hdr)`
  bisa merekonstruksi byte-identik.
- `readHeader`/`writeHeader`: tag extended dibaca/ditulis sebagai **varint**
  (mis. tag 129 = `81 01`), **bukan** 1 byte.
- Round-trip seluruh capture Fase 1 lulus 100%.

### 3.2 `relay.js` + `test-relay.js`
- 9/9 lulus: passthrough byte-identik, capture `.bin`, penanganan Zstd.
- Saat ini **tidak dipakai** untuk Fase 2 (lihat jebakan relay loop di §7).

### 3.3 `agent.js` (Frida)
Hook yang terpasang sukses di device:
```
[✓] Hooked NetUtil.PackUtil.DecodeMsgBody
[✓] Hooked GameClient.send_msg(id, sdp, no_response)
[✓] Hooked SdpPackerImpl.pack(SdpWrapper, UInt32)
[✓] Hooked GameClient.send_msg(id, byte[], ...)
[✓] Hooked 16 overload SdpUnpackerImpl.visit
[✓] Hooked 6 overload NetUtil.PackUtil.Unpack
```
- `visit` menghasilkan nama field + tag yang **benar** (dipakai `tags.jsonl`).
- `send_msg` SEND menghasilkan `raw_hex` berisi **frame wire lengkap**, contoh:
  `0x2721` (id internal) → raw `7000a14e 01 ea 01 45 7c ...`
  → opcode wire = **byte 0** (`0x7000a14e`).
- `wireOpcodeFrom(raw)`: jika byte0=`0x70` → opcode di byte0; jika byte4=`0x70` → di byte4.

### 3.4 `tools/build-schema.js`
- Selesai: parse `dump.cs` (17.926 class, 663 `Cmd_*`), filter opcode `^0x70[0-9a-f]{6}$`,
  tag dari urutan field di sesi `visit`, fallback indeks + `inferred`.
- Output `schema/schema.json` — **35 opcode → class** terisi (dari hasil `tools/match-opcodes.js`).
- Cakupan class **35/35**; cache replay **146 opcode**.

### 3.5 Validasi tag (sudah dilakukan)
- `tag = urutan field` cocok **61.046 / 62.076 (98,3%)**.
- Contoh pergeseran: `Cmd_Role_Init_SC.sClientGuide` tag 49 vs indeks 48.
- `iDiamond` tag 11 = indeks 11 (cocok).
- Artinya `dump.cs` cukup dapat dipercaya, dengan sedikit toleransi geser.

### 3.6 Hasil Fase 2 hari ini (2026-11-06): layout `ReturnMsg` + body matching

Kebijakan terakhir untuk mengekstrak opcode → class terbukti dengan **body matching**:

```text
Unpack(Type type, ReturnMsg retMsg)          // static, 2 param
  args[0] = System.Type (Il2CppReflectionType)
            -> +0x10 = Il2CppType* -> class -> Il2Cpp.Class -> class.name
            // contoh terbukti: "Cmd_Login_Auth_SC", "MTTDProto.Cmd_Hero_GetList_SC"
  args[1] = ReturnMsg (struct value di build ini)
            -> +0x0  int32  messageid     (jawaban Auth: 0x28a2 = Hero_GetList, dst.)
            -> +0x4  int32  rspcode
            -> +0x8  uint32 rspseq
            -> +0x10 ptr ke byte[] bt (ReturnMsg.bt)
                     -> bt+0x18 = panjang, bt+0x20 = data (64-bit)
```

- **Keberhasilan:** `guard` `isValidPtr()` (frida-il2cpp-bridge) **menolak pointer
  valid** di build ini (termasuk pointer heap ber-tag `0xb4...`) → semua hook body
  yang memakai guard itu gagal diam-diam. Solusi: pakai `!ptr.isNull()` saja.
- `DecodeMsgBody` retval (`ReturnMsg`) **tidak** bisa dibaca pointer-nya (selalu
  garbage `0xd02d9cb0`) → gunakan `Unpack` args sebagai satu-satunya sumber id.
- Wire body (`ParseFrame` hasil extractor) = body `Unpack` **+ 1 byte `0x80`** penutup
  → pencocokan harus strip byte terakhir bila `== 0x80`.

Alur baru yang jalan:
1. Hook `Unpack` top-level → emit `sdp_body` `{class_name, body_hex, body_len, msg_id, ...}`
   ke `mlbb_captured_tags/sdp_bodies.jsonl`.
2. Matcher `tools/match-opcodes.js` → index semua `RECV_*.json`/`SEND_*.json` dengan
   `extractBody` (scan `0x45|0x46` + varint), pasang key dengan/ tanpa terminator `0x80`.
3. Vote per opcode; body unik + hits tunggal = evidence kuat.

Output Fase 2: `tools/match-opcodes.js` → `mlbb_captured_tags/opcodes.jsonl` (32 baris),
dipakai `tools/build-schema.js` → `schema/schema.json`.

---

## 4. Blokir utama Fase 2 (INI YANG HARUS DIPECAHKAN)

**Target:** isi `mlbb_captured_tags/opcodes.jsonl` dengan `{opcode(wire), class_name}`,
lalu jalankan `node tools/build-schema.js`.

### 4.1 Fakta dari `dump.cs` (baru dikonfirmasi)

```csharp
class ReturnMsg {                       // line 156183
  [Field] 0x0  : static ReturnMsg Empty
  [Field] 0x10 : System.Int32   messageid      // id INTERNAL, bukan wire
  [Field] 0x14 : System.Int32   rspcode
  [Field] 0x18 : System.UInt32  rspseq
  [Field] 0x20 : System.Byte[]  bt
  [Field] 0x28 : System.UInt64  datatime
  [Field] 0x30 : System.UInt32  iRspCmdType
  [Field] 0x34 : System.Boolean bUseCmdSeqV2
  [Field] 0x38 : MTTDProto.SdpWrapper m_SdpWrapper
}

class RspProto {                        // line 314095
  [Field] 0x10 : System.UInt32  iRspCmdId     // <-- OPCODE WIRE (0x70xxxxxx)
  [Field] 0x14 : System.UInt32  iRspCmdSeq
  [Field] 0x18 : System.UInt32  iPushSeqId
  [Field] 0x1c : System.UInt32  iRspCmdType
  [Field] 0x20 : System.Int32   iRspCode
  [Field] 0x28 : System.Byte[]  sRspData
  [Field] 0x30 : System.UInt64  iRspCmdSeqV2
  [Field] 0x38 : System.UInt32  iRspCmdSeqCache
}

class ReqProto {                        // line 314082
  [Field] 0x10 : System.UInt32  iReqCmdId     // <-- OPCODE WIRE
  ...
}

class PackUtil {                        // line 289749 (di namespace NetUtil)
  [Field] 0x8  : static MTTDProto.RspProto res
  [Method] ReturnMsg DecodeMsgBody(System.Byte[] val, System.Int32 iRecvLen, System.UInt32 uiStartPos)
  [Method] System.Object Unpack(System.Type type, ReturnMsg retMsg)
  [Method] System.Object UnpackCached(System.Type type, ReturnMsg retMsg)
}

class GameServerConfig {                // line ~145600
  [Method] System.Void onMsgBodyCallback(GameSocketType iID, System.Byte[] val, System.Int32 iStartPos, System.Int32 iNetSize)
  [Method] System.Object Unpack(System.Type type, ReturnMsg retMsg)   // line 145696
}
```

**Kesimpulan penting:** opcode wire ada di `RspProto.iRspCmdId` / `ReqProto.iReqCmdId`,
sedangkan `ReturnMsg.messageid` adalah id internal (contoh `0x6298`, `0x2721`).
Karena itu hook `Unpack` yang membaca `messageid` **tidak akan pernah** memberi `0x70xxxxxx`.

### 4.2 Percobaan yang SUDAH GAGAL (jangan diulang)

| Percobaan | Hasil |
|---|---|
| `Unpack`: `args[1].add(0x10).readInt()` | `0x17fa7540` — bukan opcode |
| `Unpack`: `new Il2Cpp.Object(args[1])` | gagal; `params: ["RuntimeType#null","err","err","null"]` |
| `Unpack`: `tryField("messageid")` | null / error |
| `DecodeMsgBody`: `args[1]` sebagai `byte[]` | raw kosong (salah shift) |
| `DecodeMsgBody`: `args[0]` + offset array `0x20` | **belum terbukti** — debug belum pernah tercetak |

Debug terakhir yang tercatat:
```
[agent-debug] {"kind":"debug","direction":"DBG","method":"Unpack","paramCount":2,
 "isStatic":true,"args":["0x9e24a038","0x17fa7540","err","err"]}
[agent-debug] {"kind":"debug","direction":"DBG","params":["RuntimeType#null","err","err","null"]}
```
`Unpack` **static, 2 parameter** → `args[0]=Type`, `args[1]=ReturnMsg`.
Tetapi `args[1]` tidak bisa dijadikan `Il2Cpp.Object` (kemungkinan nilai struct /
pointer yang bukan objek, atau build `dump.cs` beda).

### 4.3 Pendekatan berikutnya (urutan prioritas)

1. **Hook `GameServerConfig.onMsgBodyCallback(GameSocketType, byte[] val, int iStartPos, int iNetSize)`**
   - Hitung `shift = method.isStatic ? 0 : 1`.
   - Ambil buffer: `args[shift+1]` (byte[]), `args[shift+2]` = iStartPos, `args[shift+3]` = iNetSize.
   - Offset data `System.Byte[]` di 64-bit = `0x20` (header 0x10 + bounds 0x8 + length 0x8).
   - Baca 4 byte di `startPos`, lalu `wireOpcodeFrom(raw)`.
   - Simpan ke `currentWireOpcode` **per thread**, hapus saat callback selesai.
   - Ini kemungkinan besar titik paling bersih: semua paket masuk lewat sini.
2. **Alternatif: hook `MTTDProto.RspProto.visit(SdpUnpacker, bool)`**
   - Setelah `visit` selesai, baca `iRspCmdId` (offset `0x10`) dari `args[0]` (this).
   - `visit` RspProto terjadi sebelum body di-unpack, jadi thread-local siap dipakai `visit` berikutnya.
3. **Alternatif: hook `MTTDProto.ReqProto.visit`** untuk arah SEND (sudah ada dari
   `send_msg`, tapi ini lebih tepat).
4. Setelah opcode wire tertangkap, **kelompokkan sesi tag** per
   `(thread, opcode wire, timestamp berdekatan)`; tiap sesi = satu pesan.
   Cocokkan urutan `field_name` ke class `Cmd_*` di `dump.cs` (sudah ada di
   `tools/build-schema.js`).
5. Jalankan `node tools/build-schema.js` → cek cakupan ≥95%.
6. Baru lanjut Fase 3.

> Catatan: `currentWireOpcode` saat ini **selalu kosong** karena raw `DecodeMsgBody`
> kosong. Itulah sebabnya `tags.jsonl` berisi `"opcode":"visit"`.

---

## 5. Temuan data (untuk validasi)

- Total event tag: **676.331** baris (`mlbb_captured_tags/tags.jsonl`).
  Sebagian besar `"opcode":"visit"` (tidak terpetakan).
- File `SEND_*.json`: 4.468; `RECV_*.json`: 1.309.
- Pasangan internal→wire yang terbukti dari file SEND:
  ```
  0x2721 → 0x7000a14e   0x2715 → 0x7000954e   0x2785 → 0x7000854f
  0x2783 → 0x7000834f   0x4cfd → 0x7000fd99   0x2b5d → 0x7000dd56
  0x7547 → 0x7000c7ea   0x2867 → 0x7000e750   0xa4db → 0x7000dbc9
  ```
- Tidak ada rumus sederhana id→wire (kemungkinan tabel/acak per build).
  **Jangan menebak rumus** — ambil opcode wire langsung dari buffer.
- SEND `raw_hex` = frame wire penuh (prefix panjang bisa ada/tidak).

### Contoh isi file
```
mlbb_captured_tags/SEND_0x2721_*.json
{ "opcode":"0x2721", "raw_hex":"7000a14e01ea01457c70..." }   // wire di byte 0

mlbb_captured_tags/RECV_0x6298_*.json
{ "opcode":"0x6298", "class_name":"None / Raw", "raw_hex":"" } // raw kosong (bug)
```

---

## 6. Perintah reproduksi

```bash
cd /home/petwirkepo/Downloads/files

# 1. Bangun agent
npx frida-compile agent.js -o dist/agent.js -c

# 2. Pastikan ADB hidup (wireless sering putus)
adb devices
# bila kosong:
adb kill-server && adb start-server && sleep 3 && adb devices

# 3. (Opsional) pasang reverse HANYA bila memakai relay
#    adb reverse tcp:30021 tcp:30021
#    adb reverse tcp:30101 tcp:30101

# 4. Jalankan collector (satu proses saja!)
setsid python3 -u collector.py > /tmp/opencode/collector.log 2>&1 < /dev/null &

# 5. Baru buka game (jangan attach ke game yang sudah lama berjalan)
adb shell monkey -p com.mobilelegends.taptest -c android.intent.category.LAUNCHER 1

# 6. Tes wajib
node test-sdp.js
node test-sdp.js captures/2026-11-04-09-27-04/*.bin
```

Perintah redirect trafik:
```bash
bash tools/redirect.sh on|wifi [IP-PC]|off|status
```

- `on` = USB/adb (`REDIRECT` + `adb reverse`).
- `wifi` = LAN/hotspot (`DNAT` ke IP PC, tanpa `adb reverse`); bila device
  menjadi hotspot, perangkat lain di hotspot ikut diarahkan lewat
  `PREROUTING` + `MASQUERADE`.
- Aturan bertahan sampai reboot; jalankan ulang setelah reboot atau bila IP PC
  berubah.

### 6.1 Topologi WiFi + hotspot HP root (terbukti 2026-11-09)

HP non-root **tidak bisa** dibelokkan saat berada di WiFi rumah, karena tidak
punya iptables dan router tidak melakukan DNAT. Solusi yang terbukti: jadikan HP
root sebagai gateway hotspot, lalu arahkan klien hotspot ke IP PC di WiFi
upstream.

```text
HP non-root 192.168.21.x → FTRHOST (HP root, ap0 192.168.21.153)
  → wlan0 192.168.18.162 → WiFi rumah → PC 192.168.18.163 (server)
```

Langkah:

```bash
# Di PC (harus di WiFi rumah yang sama dengan HP root)
ip -4 addr show wlan0                    # mis. 192.168.18.163
SERVER_IP=192.168.18.163 MODE=emulate DIAMOND=9999999 LEVEL=999 \
  node server/index.js

# Di PC: pasang DNAT ke HP root
adb forward tcp:2626 tcp:2626
./tools/redirect.sh wifi 192.168.18.163
# atau: ./tools/hotspot.sh on

# Di HP root: pastikan hotspot + upstream aktif
adb shell 'ip -o -4 addr show ap0'       # 192.168.21.153/24
adb shell 'ip -o -4 addr show wlan0'     # 192.168.18.162/24
adb shell 'ip route get 192.168.18.163'  # harus lewat wlan0
```

HP non-root cukup join `FTRHOST` (password `ffffffff`). Detail alasan
(client-to-client diblokir, kenapa target harus IP upstream, troubleshooting):
`docs/TOPOLOGI-WIFI-HOTSPOT.md`.

---

## 7. Jebakan yang sudah memakan waktu

1. **Relay loop.** `relay.js` pernah meneruskan ke `192.168.78.209:30021` (dirinya
   sendiri) → `[AUTH] terhubung ke upstream ...` berulang. Pastikan upstream = IP
   server resmi, bukan IP PC. Saat Fase 2, **matikan redirect** agar game konek langsung.
2. **`adb reverse` hilang** setiap `adb kill-server`/`start-server`. Pasang ulang.
3. **Collector ganda.** `setsid ... &` di dalam shell berulang bisa membuat 3+ proses
   collector. Selalu cek `pgrep -af collector.py` dan sisakan **satu**.
4. **Game membeku setelah attach.** Attach Frida ke game yang sudah lama berjalan
   membuat UI tidak merespons tap (`tags.jsonl` berhenti, screenshot identik).
   Urutan yang benar: **force-stop game → start collector → launch game**.
   Jangan attach ulang ke PID lama.
5. **Jangan `pkill -f collector.py`** dari shell yang command-nya sendiri memuat pola
   itu (bisa membunuh shell). Pakai PID eksplisit.
6. `frida-server` di port **2626**; tidak ada `su`/`adb root` → root via
   `python3 tools/rootcmd.py` bila perlu iptables.
7. `DecodeMsgBody` adalah **static** (bukti: debug `isStatic:true`), jadi `byte[]`
   ada di `args[0]`, bukan `args[1]`.
8. `dump.cs` mungkin dari build berbeda. **Jangan percaya offset mentah**; pakai
   `tryField()` metadata atau validasi dari data capture.

---

## 8. Lingkungan saat ini (2026-11-09)

- PC: `192.168.18.163` (Linux, WiFi rumah `Brajan Atas - 5G`). Working dir
  `/home/petwirkepo/Downloads/ps-ml`.
- HP root: Redmi Note 9, `adb-76aa07d10405-K46Ryp._adb-tls-connect._tcp` /
  `192.168.18.162:43783`, `wlan0 192.168.18.162`, hotspot
  `ap0 192.168.21.153` (SSID `FTRHOST`).
- HP uji non-root: join `FTRHOST`, mendapat IP `192.168.21.x`.
- Game: `com.mobile.legends` v2.2.16.1232.1 (uji 2026-11-09). Build uji repo
  tetap `com.mobilelegends.taptest` v2.2.29.1250.1.
- Frida server port `2626` (device pid berubah tiap reboot; `adb forward tcp:2626`).
- Akun uji: nama `Test-ori`, level capture 6, coin 3243, diamond capture 0.
  Override uji terakhir: `DIAMOND=9999999 LEVEL=999` (mode `emulate`).
- Repo adalah git repository.

---

## 9. Langkah berikutnya (checklist)

- [x] Hook `GameServerConfig.onMsgBodyCallback` / `RspProto.visit` untuk `currentWireOpcode`.
      Catatan: kini `currentWireOpcode` terisi lewat hook `NetUtil.PackUtil.DecodeMsgBody`
      (onEnter). `tags.jsonl` tetap memakai `"opcode":"visit"` sampai hook `visit` memang
      dipanggil untuk topologi yang dipakai sekarang.
- [x] Isi `opcodes.jsonl`, jalankan `node tools/build-schema.js`.
      → `opcodes.jsonl` 34 opcode, `schema/schema.json` 32 opcode → class.
- [ ] Cek `schema/schema.json` ≥95% opcode punya class + skema.
- [x] Fase 3: server replay/emulate berjalan via `server/index.js`.
- [x] Fase 4: guard mode (`relay` menolak override), patch body SDP.
- [x] Fase 5: `state/profile.json` → `diamond: 2626`, `level: 28`, dibaca `server/index.js`.
- [x] Level 28 terverifikasi: patch `Cmd_Role_Init_SC` tag 3 + `Cmd_Role_GetInfo_SC` tag 3.
- [x] Uji stabilitas ≥10 menit di lobby (heartbeat `0x7000954e` dibalas dari cache, uptime 10m42s).
- [ ] Tangkap ulang opcode yang masih `cache miss` (lihat `grep "cache miss" server.log`):
      `0x7000c5d5`, `0x7000ff99`, `0x7000fbb8`, `0x7000f3f8`, `0x7000efb8`,
      `0x7000db51`, `0x7000cd65`, `0x7000ac58`, `0x7000a34f`, `0x7000a951`,
      `0x7000a14f`, `0x7000ea8b`, `0x7000d551`, `0x7000f14f`, `0x7000cf53`,
      `0x7000fa55`.
- [x] Perluas cache untuk menu lain (Heroes/Inventory/Shop) lewat relay resmi.
- [x] Mode WiFi/hotspot: `./tools/redirect.sh wifi` memasang DNAT `OUTPUT`
      (device sendiri) + `PREROUTING`/`POSTROUTING` (perangkat lain di hotspot
      `ap0`), tanpa `adb reverse`. Terverifikasi login → lobby Lv. 28 / diamond
      2626 lewat LAN.
- [x] Helper `tools/hotspot.sh on|status|clients|off` dan
      `tools/redirect-watch.sh` (pasang ulang otomatis bila NAT dibersihkan
      Android).
- [ ] Preparation masih berhenti di "Retrieving data"; push `0x7000b04f` sudah
      ditambahkan setelah `0x70009f4f`, tetapi belum konklusif. Catat sebagai
      batasan yang diketahui bila tetap gagal.

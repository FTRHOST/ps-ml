# CLAUDE.md — MLBB Private Server

Panduan untuk Claude saat bekerja di repo ini. Baca bersama `PRD.md`.
Bahasa komunikasi dan komentar kode: **Indonesia**. Nama identifier: Inggris.

## Tujuan proyek

Server privat lokal untuk client MLBB milik sendiri, dibangun bertahap:
**relay (capture) → replay → emulate**. Setelah alur login→lobby berjalan, saldo
diamond di server lokal diatur ke **2626** (config `DIAMOND`, default 2626).

## Batasan yang tidak boleh dilanggar

1. **Mode `relay` = passthrough.** Jangan pernah mengubah, menyuntik, atau menghapus byte
   yang menuju/berasal dari server resmi. Hanya mencatat.
2. **Override diamond hanya di mode `emulate`** (server lokal). Tambahkan guard: bila
   upstream resmi aktif, override ditolak dan error dilempar.
3. Jangan menambah kode untuk membypass anti-cheat, proteksi client, atau enkripsi
   layanan. Bila ada lapisan enkripsi/kompresi, dokumentasikan dan tangani seperlunya
   untuk membaca trafik milik sendiri.
4. Jangan commit `captures/`, `state/`, `relay-captures/`, `mlbb_captured_tags/`, APK,
   `dump.cs`, atau data akun/session key. Pastikan ada di `.gitignore`.
5. Hanya untuk perangkat dan akun uji milik pengguna; bukan untuk melayani pemain lain.

Jika sebuah tugas menuntut melanggar butir di atas, berhenti dan tanyakan.

## Struktur repo (target)

```
agent.js            # Frida agent (di-bundle: dist/agent.js)
collector.py        # runner ADB + Frida, simpan paket ke mlbb_captured_tags/
sdp.js              # decode/encode SDP + frame (sudah ada, jangan rusak API-nya)
test-sdp.js         # test round-trip
decode-packet.js    # CLI decoder lama (boleh diganti memakai sdp.js)
relay.js            # (Fase 1) relay TCP + logger frame
server/
  index.js          # listener Auth 30021 + Zone 30101
  handlers/         # satu file per opcode: 0x7000xxxx.js
  state/            # profile.json (diamond, level, dsb.)
schema/schema.json  # (Fase 2) opcode -> class -> {tag, name, type, require}
captures/           # sesi capture (.bin + .json), di-gitignore
unhandled/          # paket yang belum punya handler, di-gitignore
```

## Perintah

```bash
# Build agent Frida
npm i -D frida-compile frida-il2cpp-bridge
npx frida-compile agent.js -o dist/agent.js -c

# Jalankan capture (ADB + frida-server harus aktif di perangkat, port 2626)
python collector.py

# Test SDP (wajib hijau sebelum commit)
node test-sdp.js
node test-sdp.js captures/<sesi>/*.bin     # semua capture harus lulus round-trip
node test-sdp.js -v file.bin               # tampilkan pohon hasil decode

# Server (mode lewat env)
MODE=relay   node relay.js
MODE=replay  node server/index.js
MODE=emulate DIAMOND=2626 node server/index.js
```

## Fakta protokol

**Terverifikasi dari data asli** (bulletin SC, reject `-45`, paket buatan `auth-server.js`):
- Frame: `[len u32BE][opcode u32BE][seq u8][02 00][05 00 46][varint(bodyLen-1)][body]`
  - `len` = total frame termasuk 8 byte header awal.
  - `bodyLen-1` karena `80` penutup terakhir tidak dihitung.
  - Server→client memakai `46`, client→server `45`.
- Varian "compact" (mis. reject Cold Start): `[len][opcode][seq][body]` tanpa envelope,
  contoh `0000000c 70000201 01 152d 80`.
- Header field: `byte = (type<<4)|tag`; bila tag ≥ 15: `(type<<4)|0x0F` lalu 1 byte tag.
- Tipe: `0` varint positif, `1` **integer negatif** (magnitude varint, bukan Int64 fixed),
  `2` float LE, `3` double LE, `4` string (varint len), `5` list (varint count),
  `6` map, `7` StructBegin, `8` StructEnd.
- Body normal: root struct tag 0 + satu `80` tambahan di akhir.
- Elemen list struct diawali `70` (header bertag 0).

**Belum terverifikasi** (cek dengan capture asli, jangan dianggap pasti):
- Elemen list/map non-struct (angka/string) memakai header bertag 0.
- Paket Zstd (`0x1000`) dan format probe Cold Start.
- Opcode SC tidak selalu CS+0x100; ambil dari tabel `PackUtil.Unpack`.
- Isi `Cmd_Net_Echo_SC` / `Cmd_Net_ServerTime_SC`.

## Sumber kebenaran

- **Struktur class & nama field:** `dump.cs` (ada 291 class `Cmd_*_SC`, 380 `Cmd_*_CS`).
  Contoh: `Cmd_Role_Init_SC.iDiamond` (`Int32`, offset `0x4c`).
- **Nomor tag:** `mlbb_captured_tags/tags.jsonl` (`tag`, `field_name`, `require`,
  `thread`). Nomor tag **tidak ada** di `dump.cs`.
- **Byte asli:** hasil `captures/`. Bila konflik dengan asumsi, capture yang menang.

## Konvensi kode

- Node CommonJS, tanpa dependensi runtime kecuali perlu. Python 3.10+.
- Integer 64-bit selalu `BigInt` di `sdp.js`; jangan konversi ke `Number` tanpa batas aman.
- Satu handler per opcode, menerima `(ctx, request)` dan mengembalikan **objek node
  bernama** (bukan hex mentah). Jangan menempel hex besar di kode; simpan di `captures/`.
- Opcode tak dikenal: **jangan echo kosong**. Simpan ke `unhandled/` dan log jelas.
- Log: satu baris per paket `[PORT] ARAH opcode (nama) seq len`, hex dump hanya dengan
  `-v`/`DEBUG=1`.
- Komentar menjelaskan *mengapa*, terutama untuk asumsi protokol.

## Cara kerja yang diharapkan

1. Sebelum mengubah `sdp.js`: jalankan `node test-sdp.js` (dan seluruh capture bila ada).
2. Setiap perilaku protokol baru → tambahkan vektor test dari data asli, bukan data
   yang dikarang sendiri.
3. Perubahan encoder wajib round-trip terhadap capture: `encode(decode(x)) == x`.
4. Kerjakan per fase di `PRD.md`; jangan lompat ke Fase 4–5 sebelum Fase 1–3 lulus.
5. Bila respons server berbeda dari capture asli, bandingkan **field per field**
   (mis. `Auth_SC` buatan sendiri 126 B vs 81 B di komentar kode lama).
6. Ringkas di akhir tiap tugas: apa yang diubah, apa yang diuji, apa yang masih asumsi.

## Fitur diamond = 2626 (Fase 5)

- Sumber nilai: `server/state/profile.json` → `diamond` (default dari env `DIAMOND`).
- Handler `Cmd_Role_Init_SC` mengisi `iDiamond` dari state. Semua respons lain yang
  membawa saldo wajib membaca state yang sama.
- Cari opcode lain yang memuat diamond dari capture (toko, hadiah, push update);
  jangan menebak nomor tag, ambil dari `schema.json`.
- Terima bila: UI menampilkan 2626, tetap 2626 setelah relogin, tidak ada trafik ke
  server resmi selama pengujian.

## Status saat ini

- [x] Agent Frida (`agent.js`), collector, hook pack untuk SEND
- [x] `sdp.js` + `test-sdp.js` (7/7 lulus pada vektor bawaan)
- [x] Prototipe `auth-server.js` (Auth, CheckUpgrade, Bulletin, Net_Connect)
- [ ] Fase 1: relay + capture penuh
- [ ] Fase 2: `schema.json` + tabel opcode
- [ ] Fase 3: replay stabil sampai lobby
- [ ] Fase 4: handler emulate per opcode
- [ ] Fase 5: diamond 2626

## Pertanyaan yang sebaiknya diajukan ke pengguna

- Versi Frida (16 atau 17) dan apakah perangkat root?
- Sudah ada capture `.bin` asli? Bila belum, mulai dari Fase 1.
- Apakah trafik terenkripsi/terkompresi selain probe `0x1000`?

# PRD — MLBB Private Server (Relay → Replay → Emulate)

**Status:** Draft v1 · **Bahasa dokumen:** Indonesia · **Pemilik:** (isi)

## 1. Ringkasan

Membangun server privat lokal yang dapat melayani client MLBB milik sendiri, dengan
cara: (1) **menangkap** trafik asli lewat relay, (2) **memahami** protokol SDP,
(3) **memutar ulang** respons hasil tangkapan, lalu (4) **mengemulasi** respons secara
parametrik. Setelah seluruh alur login sampai lobby berhasil ditangkap dan berjalan di
server lokal, saldo **diamond di server privat diatur menjadi `2626`**.

Tujuan akhirnya adalah riset interoperabilitas dan pembelajaran protokol, bukan
mengubah layanan resmi.

## 2. Tujuan dan Non-Tujuan

### Tujuan
- G1. Relay yang mencatat semua frame client↔server (kedua arah) tanpa mengubah isinya.
- G2. Library SDP yang decode→encode **identik byte per byte** untuk semua capture.
- G3. Server lokal yang menyelesaikan alur: probe `0x1000` → Auth → GetZone →
  CheckUpgrade → GetBulletin → Net_Connect → Role_Init → lobby stabil (heartbeat jalan).
- G4. Skema field bernama (`iDiamond`, `sName`, …) untuk setiap opcode yang ditangkap.
- G5. Diamond = **2626** di server privat, tampil benar di UI client dan konsisten
  setelah relogin.

### Non-tujuan (dan batasan keras)
- N1. **Tidak** mengubah, menyuntik, atau memodifikasi paket yang menuju **server resmi**.
  Mode relay hanya *passthrough + logging*.
- N2. Modifikasi diamond **hanya** ada di mode `emulate` (server lokal). Nilai itu tidak
  memengaruhi akun atau server resmi.
- N3. Tidak membypass anti-cheat, enkripsi, atau proteksi client. Jika ada lapisan
  enkripsi/kompresi, ia didokumentasikan dan ditangani sebatas yang diperlukan untuk
  membaca trafik milik sendiri.
- N4. Tidak mendistribusikan aset, APK, atau data akun Moonton. Capture berisi data akun
  pribadi dan tidak boleh di-commit ke repo publik.
- N5. Tidak ditujukan untuk penggunaan publik/komersial, tidak membuka server untuk
  pemain lain.
- N6. Mengakui risiko ToS: penggunaan akun asli lewat relay bisa melanggar ketentuan
  layanan. Gunakan akun uji sendiri.

## 3. Arsitektur

```
 Client (Android, Frida agent)  ──►  Relay (Node, port lokal)  ──►  Server resmi
                                        │ log frame (.bin + .json)
                                        ▼
                                  captures/  ──►  decoder (sdp.js) ──► schema.json
                                                                          │
 Client  ──►  Server lokal (mode replay / emulate)  ◄── handlers + state ◄┘
```

Tiga mode, satu codebase:

| Mode | Perilaku | Mengubah data? |
|---|---|---|
| `relay` | Meneruskan byte apa adanya ke server resmi, mencatat | **Tidak** |
| `replay` | Menjawab dari capture (ganti seq/waktu/session key saja) | Minimal |
| `emulate` | Menjawab dari handler + state lokal (termasuk diamond 2626) | Ya (lokal) |

Komponen yang sudah ada: `agent.js` (Frida: hook DecodeMsgBody, pack, send_msg, visit),
`collector.py` (runner ADB+Frida), `decode-packet.js`, `sdp.js` + `test-sdp.js`,
`auth-server.js` (prototipe server).

## 4. Fase dan Kriteria Penerimaan

### Fase 0 — Fondasi (selesai sebagian)
- `sdp.js` lulus round-trip pada bulletin, reject `-45`, dan paket buatan sendiri.
- **Selesai bila:** `node test-sdp.js` hijau.

### Fase 1 — Relay & Capture
- FR-1.1 Relay TCP untuk port Auth (30021) dan Zone (30101) → upstream resmi.
- FR-1.2 Parser frame streaming (menangani paket terpecah/menempel) dan deteksi
  probe `0x1000` / Zstd.
- FR-1.3 Simpan tiap frame: `captures/<sesi>/<nomor>-<arah>-<opcode>.bin` + metadata
  JSON (waktu, panjang, seq).
- FR-1.4 Frame yang tidak dikenali diteruskan utuh dan ditandai, tidak dibuang.
- **Selesai bila:** satu sesi login→lobby→buka profil→buka toko tercatat penuh, dan
  `node test-sdp.js captures/<sesi>/*.bin` **100% lulus**.

### Fase 2 — Skema & Peta Opcode
- FR-2.1 Hook `PackUtil.Unpack` → tabel `opcode → nama class`.
- FR-2.2 Gabungkan `tags.jsonl` + `dump.cs` → `schema.json` (tag, nama, tipe, require).
- FR-2.3 `toText(nodes, names)` menampilkan nama field.
- **Selesai bila:** ≥ 95% opcode yang tertangkap di Fase 1 punya nama class dan skema.

### Fase 3 — Replay
- FR-3.1 Server lokal menjawab setiap request dengan respons capture yang sesuai.
- FR-3.2 Field dinamis diganti: seq, `iServerTimeMS`, session key, alamat server.
- FR-3.3 Opcode tak dikenal **tidak** di-echo kosong; dicatat ke `unhandled/` beserta bytes.
- **Selesai bila:** client mencapai lobby tanpa error dan bertahan ≥ 10 menit
  (heartbeat/echo/server-time benar).

### Fase 4 — Emulate
- FR-4.1 Satu handler per opcode (`handlers/<opcode>.js`) memakai skema, bukan hex mentah.
- FR-4.2 `state/` menyimpan profil lokal (JSON) yang dibaca handler.
- FR-4.3 Setiap respons di-encode dari objek bernama, lalu diuji round-trip terhadap
  respons capture saat state = nilai capture.
- **Selesai bila:** respons emulate untuk state bawaan identik dengan capture
  (kecuali field dinamis).

### Fase 5 — Diamond = 2626 (di server lokal)
Lihat bagian 5.

## 5. Fitur: Diamond 2626

**Titik data yang sudah diketahui (dari `dump.cs`):**
- `Cmd_Role_Init_SC.iDiamond` — `Int32`, offset `0x4c`. Ini sumber saldo saat login.
- Kemungkinan ada push update terpisah (class `Cmd_*` yang memuat diamond/currency)
  dan kunci `MLBTPlayerProperty.Diamond` di sisi client. Daftar pastinya ditentukan dari
  capture, bukan ditebak.

**Persyaratan:**
- FR-5.1 `state/profile.json` memiliki `diamond: 2626` sebagai nilai awal.
- FR-5.2 Handler `Cmd_Role_Init_SC` mengisi `iDiamond` dari state (bukan konstanta
  tersebar di kode).
- FR-5.3 Semua respons lain yang membawa saldo diamond (hasil Tahap Capture: toko,
  hadiah, push update) membaca state yang sama, sehingga tidak ada angka yang
  bertentangan.
- FR-5.4 Mode `relay` dan `replay-dari-server-resmi` **tidak pernah** menyentuh field
  diamond. Guard di kode: hanya `emulate` yang boleh menerapkan override, dan nilai itu
  ditolak bila upstream resmi aktif.
- FR-5.5 Perubahan nilai lewat konfigurasi (`DIAMOND=2626`), bukan hardcode.

**Kriteria penerimaan:**
1. Setelah login, UI client menampilkan **2626**.
2. Setelah logout/login ulang, tetap 2626.
3. Membuka toko/fitur yang menampilkan diamond tidak menunjukkan angka lain.
4. Tidak ada lalu lintas ke server resmi selama pengujian (diverifikasi lewat log
   relay/`tcpdump`).
5. Bila client mengirim request yang mengurangi diamond dan handler belum ada, server
   mencatat opcode tersebut ke `unhandled/` (tidak diam-diam dibalas "sukses").

## 6. Persyaratan Non-Fungsional

- NF-1 Reproducible: satu perintah untuk build agent, jalankan collector, jalankan server.
- NF-2 Observability: log berwarna per opcode, hex dump opsional, setiap frame bisa
  dibuka ulang dari file.
- NF-3 Keamanan data: `captures/` dan `state/` masuk `.gitignore`; data akun disamarkan
  bila dibagikan.
- NF-4 Kompatibilitas: Frida 16 dan 17, Node ≥ 18, Python ≥ 3.10.
- NF-5 Uji: tiap perubahan di `sdp.js` wajib menjalankan round-trip seluruh capture.

## 7. Risiko dan Mitigasi

| Risiko | Dampak | Mitigasi |
|---|---|---|
| Trafik terenkripsi/terkompresi sebagian (Zstd, session key) | Capture tidak terbaca | Deteksi lapisan di parser frame; dokumentasikan; tangkap di level pasca-dekripsi (hook `DecodeMsgBody`/`pack`) |
| Client memvalidasi signature/versi | Server lokal ditolak | Bandingkan field dengan respons asli; replay dulu sebelum emulate |
| Opcode SC tidak mengikuti pola CS+0x100 | Handler salah | Ambil pemetaan dari `PackUtil.Unpack`, bukan dari pola |
| Akun dikenai tindakan karena memakai relay ke server resmi | Kehilangan akun | Pakai akun uji; batasi sesi capture; jangan ubah paket |
| Data pribadi bocor lewat capture | Privasi | `.gitignore`, redaksi session key/ID |

## 8. Pertanyaan Terbuka

1. Apakah ada pemeriksaan integritas (checksum/HMAC) pada frame di luar `sSignature`?
2. Opcode apa saja yang membawa saldo diamond selain `Cmd_Role_Init_SC`?
3. Apakah heartbeat (`Cmd_Net_Echo_SC`, `Cmd_Net_ServerTime_SC`) membutuhkan isi tertentu?
4. Bagaimana client menangani error code selain `-45` pada Auth?

## 9. Definition of Done (keseluruhan)

- [ ] Fase 1–5 memenuhi kriteria penerimaannya.
- [ ] `node test-sdp.js captures/**/*.bin` 100% lulus.
- [ ] Client login → lobby di server lokal, diamond **2626**, stabil ≥ 10 menit.
- [ ] README berisi langkah reproduksi dan daftar opcode yang belum ditangani.

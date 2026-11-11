#!/usr/bin/env node
/**
 * relay.js — Relay TCP + pencatat frame (Fase 1, PRD FR-1.1 … FR-1.4).
 *
 * ATURAN KERAS (PRD N1 / CLAUDE.md butir 1):
 *   Relay ini HANYA meneruskan byte apa adanya ke server resmi dan mencatatnya.
 *   Tidak ada pun byte yang diubah, disuntik, atau dibuang — termasuk saat
 *   parsing gagal. Kode di file ini sengaja tidak punya jalur "modify".
 *
 * Cara kerja pencatatan:
 *   1. Setiap chunk TCP diteruskan dulu ke peer (byte identik, tanpa menunggu).
 *   2. Baru kemudian chunk ditambahkan ke buffer parser untuk dipotong per frame.
 *      Karena parsing tidak memengaruhi pengiriman, frame yang terpecah/tertahan
 *      tidak pernah menunda trafik.
 *
 * Frame yang dikenal:
 *   - normal  : [len u32BE][opcode u32BE][seq][02 00][05 00 46/45][varint bodyLen-1][body]
 *   - probe   : [10 00][total u16BE][payload zstd]   (cold-start / Zstd, FR-1.2)
 *
 * Frame yang tidak dikenal (FR-1.4): diteruskan utuh, ditandai `unknown:true`
 * di metadata, dan disimpan sebagai .bin bertanda `unknown` — tidak dibuang.
 *
 * Paket Zstd disimpan apa adanya dengan ekstensi `.zstd` (bukan `.bin`) karena
 * kompresi zstd tidak bisa di-round-trip byte-per-byte oleh sdp.js; PRD Fase 1
 * mensyaratkan `test-sdp.js captures/<sesi>/*.bin` lulus 100%.
 *
 * Pakai:
 *   MODE=relay node relay.js
 *   DEBUG=1 node relay.js        # hex dump per frame
 *   node relay.js -v             # sama dengan DEBUG=1
 */
const net = require("net");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const sdp = require("./sdp");

// ---------------------------------------------------------------------------
// Konfigurasi
// ---------------------------------------------------------------------------
const HOST = process.env.HOST || "0.0.0.0";
/**
 * Port lokal yang didengarkan, dipisah koma. Versi klien berbeda memakai port
 * berbeda (contoh nyata: 30021/30101 pada build lama, 30071/10003 pada build
 * 2.2.29), jadi relay mendengarkan semuanya sekaligus.
 */
function parsePorts(value, fallback) {
  const raw = value === undefined || value === "" ? fallback : String(value);
  return raw
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
}
const AUTH_PORTS = parsePorts(process.env.AUTH_PORT, "30021,30071");
const ZONE_PORTS = parsePorts(process.env.ZONE_PORT, "30101,10003");
const CAPTURE_ROOT = path.join(__dirname, "captures");
const DEBUG = !!(process.env.DEBUG || process.argv.includes("-v"));

/** Batas frame yang masuk akal; di luar itu dianggap framing rusak. */
const MAX_FRAME = 16 * 1024 * 1024;
/** Pemisah daftar upstream: `host:port`. */
function parseAddr(value, fallback) {
  if (!value && fallback === null) return null;
  const s = String(value || fallback);
  const i = s.lastIndexOf(":");
  if (i < 0) return { host: s, port: 30000 };
  return { host: s.slice(0, i), port: Number(s.slice(i + 1)) };
}
// Upstream resmi. Relay TIDAK boleh menunjuk ke server lokal (lihat FR-5.4).
const AUTH_UPSTREAM = parseAddr(
  process.env.AUTH_UPSTREAM,
  "login.ml.youngjoygame.com:30021",
);
const ZONE_UPSTREAM = parseAddr(
  process.env.ZONE_UPSTREAM,
  "148.153.165.215:10003",
);

// Objek layanan dibuat sekali lalu dirujuk, supaya target zone bisa diperbarui
// saat relay membaca CheckUpgrade_SC (lihat learnZoneTarget). Semua port zone
// berbagi satu alamat upstream karena server menetapkan satu zone per sesi.
const ZONE_SERVICES = ZONE_PORTS.map((port) => ({
  name: "ZONE",
  localPort: port,
  upstream: ZONE_UPSTREAM,
}));
const AUTH_SERVICES = AUTH_PORTS.map((port) => ({
  name: "AUTH",
  localPort: port,
  upstream: AUTH_UPSTREAM,
}));

/**
 * Belajar alamat zone dari Cmd_Login_CheckUpgrade_SC (tag 1 = sConnServer).
 *
 * Kenapa ini perlu: iptables REDIRECT di device menghapus tujuan asli, sehingga
 * relay tidak tahu IP zone yang diminta client. Server memberi tahu lewat
 * CheckUpgrade_SC, jadi kita baca (read-only) lalu pakai untuk koneksi berikutnya.
 * Tanpa ini relay salah menembak IP zone dan client loop reconnect.
 *
 * Hanya MEMBACA byte; tidak ada pun yang ditulis ulang.
 */
function learnZoneTarget(bytes) {
  try {
    let inner = bytes;
    if (bytes.length > 4 && bytes.readUInt16BE(0) === 0x1000) {
      inner = zstdDecompress(bytes.subarray(4));
      if (!inner || inner.length < 9) return null;
    }
    if (inner.readUInt32BE(0) !== 0x70000601) return null;
    const frame = sdp.parseFrame(inner);
    const nodes = sdp.decode(frame.body);
    const conn = nodes.find((n) => n.tag === 1 && n.type === sdp.T.STRING);
    if (!conn) return null;
    const target = conn.raw.toString("utf8");
    const addr = parseAddr(target, null);
    if (!addr || !addr.host || !addr.port) return null;
    const current = ZONE_SERVICES[0].upstream;
    const before = `${current.host}:${current.port}`;
    const next = `${addr.host}:${addr.port}`;
    if (before !== next) {
      for (const svc of ZONE_SERVICES) svc.upstream = addr;
      console.log(
        `[relay] target zone diperbarui: ${before} -> ${next} (dari CheckUpgrade_SC)`,
      );
    }
    return next;
  } catch (_) {
    return null; // bukan CheckUpgrade / gagal decode: biarkan target lama
  }
}

/** Nama opcode — dipakai untuk log & metadata (bukan untuk memodifikasi byte). */
const OPCODE_NAMES = loadOpcodeNames();

function loadOpcodeNames() {
  const base = {
    0x70000101: "Cmd_Login_Auth_CS",
    0x70000201: "Cmd_Login_Auth_SC",
    0x70000301: "Cmd_Login_GetZone_CS",
    0x70000401: "Cmd_Login_GetZone_SC",
    0x70000501: "Cmd_Login_CheckUpgrade_CS",
    0x70000601: "Cmd_Login_CheckUpgrade_SC",
    0x70000701: "Cmd_Login_GetBulletin_CS",
    0x70000801: "Cmd_Login_GetBulletin_SC",
    0x70000d01: "Cmd_Login_Echo_CS",
    0x70000e01: "Cmd_Login_Echo_SC",
    0x7000914e: "Cmd_Net_Connect_CS",
    0x7000924e: "Cmd_Net_Connect_SC",
    0x7000954e: "Cmd_Net_Echo_CS",
    0x7000964e: "Cmd_Net_Echo_SC",
    0x7000f54e: "Cmd_Role_Init_CS",
    0x7000f64e: "Cmd_Role_Init_SC",
  };
  // Fase 2: bila schema.json sudah ada, tambahkan nama dari sana.
  try {
    const schemaPath = path.join(__dirname, "schema", "schema.json");
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
    for (const [op, entry] of Object.entries(schema.opcodes || {})) {
      if (entry && entry.class) base[Number(op)] = entry.class;
    }
  } catch (_) {
    /* schema belum ada — bukan masalah */
  }
  return base;
}

// ---------------------------------------------------------------------------
// Util
// ---------------------------------------------------------------------------
function hexdump(buf, maxLen = 128) {
  const slice = buf.subarray(0, maxLen);
  const lines = [];
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(chunk)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(
      `      ${i.toString(16).padStart(4, "0")}: ${hex.padEnd(47, " ")} | ${ascii}`,
    );
  }
  if (buf.length > maxLen)
    lines.push(`      ... (${buf.length} maxLen=${maxLen})`);
  return lines.join("\n");
}

function zstdDecompress(buf) {
  try {
    const zlib = require("zlib");
    if (typeof zlib.zstdDecompressSync === "function") {
      return zlib.zstdDecompressSync(buf);
    }
  } catch (_) {}
  try {
    // fallback CLI: stderr diabaikan
    return cp.execFileSync("zstd", ["-d", "-q"], {
      input: buf,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["pipe", "pipe", "ignore"],
    });
  } catch (_) {
    return null; // zstd tidak tersedia / payload bukan zstd — logging saja, bukan error
  }
}

const pad = (n, w = 4) => String(n).padStart(w, "0");
const hex32 = (n) => "0x" + (n >>> 0).toString(16);

// ---------------------------------------------------------------------------
// Session capture
// ---------------------------------------------------------------------------
class CaptureSession {
  constructor(root) {
    const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
    this.dir = path.join(root, stamp);
    this.seq = 0;
    this.jsonl = null;
    this.started = false;
    this.root = root;
  }

  ensure() {
    if (this.started) return;
    fs.mkdirSync(this.dir, { recursive: true });
    this.jsonl = path.join(this.dir, "frames.jsonl");
    fs.writeFileSync(this.jsonl, "");
    this.started = true;
    console.log(`[*] Sesi capture: ${path.relative(process.cwd(), this.dir)}`);
  }

  /**
   * Simpan satu frame + metadata (FR-1.3).
   * @param {object} info  { dir, port, kind, opcode, seq, envelope, bytes, ts, extra }
   * @param {Buffer} bytes byte ASLI (tidak pernah dimodifikasi)
   */
  save(info) {
    this.ensure();
    this.seq += 1;
    const opPart =
      info.opcode == null
        ? "unknown"
        : hex32(info.opcode).slice(2).padStart(8, "0");
    const ext = info.kind === "zstd" ? "zstd" : "bin";
    const unknownPart = info.unknown ? "-unknown" : "";
    const base = `${pad(this.seq)}-${info.dir}-${opPart}${unknownPart}`;
    fs.writeFileSync(path.join(this.dir, `${base}.${ext}`), info.bytes);

    const meta = {
      seq: this.seq,
      dir: info.dir, // c2s | s2c
      port: info.port,
      kind: info.kind, // frame | zstd | unknown
      opcode: info.opcode == null ? null : hex32(info.opcode),
      opcode_name:
        info.opcode == null ? null : OPCODE_NAMES[info.opcode] || null,
      envelope: info.envelope || null,
      length: info.bytes.length,
      timestamp: info.ts || Date.now(),
      unknown: !!info.unknown,
      ...(info.extra || {}),
    };
    fs.writeFileSync(
      path.join(this.dir, `${base}.json`),
      JSON.stringify(meta, null, 2),
    );
    fs.appendFileSync(this.jsonl, JSON.stringify(meta) + "\n");
    return meta;
  }
}

// ---------------------------------------------------------------------------
// Parser frame streaming (FR-1.2)
// ---------------------------------------------------------------------------
/**
 * Memotong aliran byte menjadi frame. Menerima chunk apa pun (bisa terpecah
 * di tengah frame, bisa juga berisi beberapa frame menempel).
 *
 * `onFrame({kind, bytes, opcode, seq, envelope, unknown})` dipanggil per frame.
 * Bytes yang keluar SELALU subslice asli dari input — tidak pernah ditulis ulang.
 */
class FrameParser {
  constructor(onFrame) {
    this.buf = Buffer.alloc(0);
    this.onFrame = onFrame;
  }

  push(chunk) {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    let guard = 0;
    while (this.buf.length >= 4) {
      if (++guard > 100000) break; // pengaman loop
      const b = this.buf;

      // --- probe / Zstd: [10 00][total u16BE][payload] ---
      if (b[0] === 0x10 && b[1] === 0x00) {
        const total = b.readUInt16BE(2);
        if (total < 4) {
          this.emitUnknown(4, "panjang probe tidak masuk akal");
          continue;
        }
        if (b.length < total) break; // tunggu data lengkap
        const bytes = b.subarray(0, total);
        const inner = zstdDecompress(bytes.subarray(4));
        const opcode =
          inner && inner.length >= 8 ? inner.readUInt32BE(0) : null;
        const seq = inner && inner.length > 8 ? inner[8] : null;
        this.onFrame({
          kind: "zstd",
          bytes,
          opcode,
          seq,
          envelope: "zstd",
          unknown: false,
          extra: { probe: true, inner_length: inner ? inner.length : null },
        });
        this.buf = b.subarray(total);
        continue;
      }

      // --- frame normal: [len u32BE][opcode u32BE]... ---
      const len = b.readUInt32BE(0);
      if (len < 9 || len > MAX_FRAME) {
        // Framing tidak dikenal (FR-1.4): teruskan juga byte-nya, tandai.
        this.emitUnknown(4, `len=${len} di luar rentang`);
        continue;
      }
      if (b.length < len) break; // tunggu data lengkap
      const bytes = b.subarray(0, len);
      const opcode = bytes.readUInt32BE(4);
      const seq = bytes.length > 8 ? bytes[8] : null;
      let envelope = "compact";
      if (
        bytes.length > 13 &&
        bytes[9] === 0x02 &&
        bytes[10] === 0x00 &&
        bytes[11] === 0x05 &&
        bytes[12] === 0x00 &&
        (bytes[13] === 0x46 || bytes[13] === 0x45)
      ) {
        envelope = bytes[13] === 0x46 ? "game-sc" : "game-cs";
      }
      this.onFrame({
        kind: "frame",
        bytes,
        opcode,
        seq,
        envelope,
        unknown: false,
        extra: {},
      });
      this.buf = b.subarray(len);
    }
  }

  /**
   * Buang byte framing-rusak sebagai frame `unknown`, lalu coba resync ke
   * awal frame berikutnya yang masuk akal. Byte tetap diteruskan oleh relay;
   * di sini hanya untuk pencatatan.
   */
  emitUnknown(consume, reason) {
    const b = this.buf;
    if (b.length < 4) return; // belum cukup data untuk diputuskan
    const resync = this.findResync(consume);
    // Tanpa titik sinkronisasi yang plausibel, seluruh sisa buffer adalah data
    // non-protokol (mis. laporan teks login). Simpan sebagai SATU potongan;
    // memecah 4 byte per file hanya menghasilkan ribuan artefak palsu.
    const cut = resync >= 0 ? Math.max(consume, resync) : b.length;
    const bytes = b.subarray(0, cut);
    this.onFrame({
      kind: "unknown",
      bytes,
      opcode: null,
      seq: null,
      envelope: null,
      unknown: true,
      extra: { reason },
    });
    this.buf = b.subarray(cut);
  }

  /**
   * Cari offset awal frame berikutnya yang plausibel setelah `from`.
   * Validasi dibuat ketat: kandidat harus punya penanda amplop game
   * (`02 00 05 00 45|46`) supaya teks acak tidak dianggap frame.
   */
  findResync(from) {
    const b = this.buf;
    for (let i = from; i + 14 <= b.length; i++) {
      if (b[i] === 0x10 && b[i + 1] === 0x00 && b.readUInt16BE(i + 2) >= 4)
        return i;
      const len = b.readUInt32BE(i);
      if (len < 9 || len > MAX_FRAME) continue;
      const op = b.readUInt32BE(i + 4);
      if (op === 0) continue; // opcode 0 tidak valid sebagai penanda frame
      const envelope =
        b[i + 9] === 0x02 &&
        b[i + 10] === 0x00 &&
        b[i + 11] === 0x05 &&
        b[i + 12] === 0x00 &&
        (b[i + 13] === 0x45 || b[i + 13] === 0x46);
      if (!envelope) continue;
      return i;
    }
    return -1;
  }

  flush() {
    if (this.buf.length === 0) return;
    const bytes = this.buf;
    this.buf = Buffer.alloc(0);
    this.onFrame({
      kind: "unknown",
      bytes,
      opcode: null,
      seq: null,
      envelope: null,
      unknown: true,
      extra: { reason: "sisa buffer saat koneksi ditutup" },
    });
  }
}

// ---------------------------------------------------------------------------
// Resolusi tujuan asli (FR-1.2: jangan salah kirim ke server lain)
// ---------------------------------------------------------------------------
// iptables REDIRECT mengganti tujuan paket, tetapi socket di device MASIH
// menyimpan tujuan aslinya (terbukti: /proc/net/tcp menampilkan IP zone yang
// diminta client). Kita baca IP itu lewat adb lalu memakainya sebagai upstream,
// sehingga relay meneruskan ke server yang benar diminta client.
// Bila gagal, jatuh ke (1) hasil baca CheckUpgrade_SC lalu (2) konfigurasi env.
const destCache = new Map(); // port -> ip terakhir yang terbaca

function decodeProcIp(hex8) {
  if (!/^[0-9a-f]{8}$/i.test(hex8)) return null;
  const b = [
    hex8.slice(6, 8),
    hex8.slice(4, 6),
    hex8.slice(2, 4),
    hex8.slice(0, 2),
  ].map((h) => parseInt(h, 16));
  return b.join(".");
}

/** Baca tujuan asli koneksi keluar ke `port` dari /proc/net/tcp device. */
function lookupDeviceDest(port) {
  return new Promise((resolve) => {
    cp.execFile(
      "adb",
      ["shell", "cat /proc/net/tcp"],
      { timeout: 2000, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout) => {
        if (err) return resolve(null);
        let best = null;
        for (const line of String(stdout).split("\n").slice(1)) {
          const f = line.trim().split(/\s+/);
          if (f.length < 10) continue;
          const rport = parseInt(f[2].split(":")[1] || "", 16);
          if (rport !== port) continue;
          const state = f[3];
          if (state !== "01" && state !== "02") continue; // ESTABLISHED / SYN_SENT
          const ip = decodeProcIp(f[2].split(":")[0]);
          if (!ip || ip === "127.0.0.1" || ip === "0.0.0.0") continue;
          const inode = Number(f[9]) || 0;
          if (!best || inode > best.inode) best = { ip, inode }; // terbaru
        }
        resolve(best ? best.ip : null);
      },
    );
  });
}

async function resolveUpstream(service) {
  const port = service.localPort;
  const ip = await lookupDeviceDest(port);
  if (ip) {
    destCache.set(port, ip);
    return { host: ip, port };
  }
  if (destCache.has(port)) return { host: destCache.get(port), port };
  return service.upstream; // fallback terakhir: konfigurasi env
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------
const session = new CaptureSession(CAPTURE_ROOT);

function serve(service) {
  const server = net.createServer((client) => {
    const peer = new net.Socket();
    let closed = false;
    const label = service.name;

    // Parser arah C2S dan S2C dipisah supaya penomoran frame tidak tertukar.
    const mkParser = (dir) =>
      new FrameParser((f) => {
        const meta = session.save({
          dir,
          port: service.localPort,
          kind: f.kind,
          opcode: f.opcode,
          seq: f.seq,
          envelope: f.envelope,
          bytes: f.bytes,
          unknown: f.unknown,
          extra: f.extra,
        });
        // CheckUpgrade_SC memberi tahu alamat zone; baca saja (tanpa mengubah)
        // supaya koneksi zone berikutnya diteruskan ke tujuan yang benar.
        if (f.opcode === 0x70000601) learnZoneTarget(f.bytes);
        const name = meta.opcode_name || (meta.opcode ? "" : meta.kind);
        console.log(
          `[${service.localPort}] ${dir.toUpperCase()} ${meta.opcode || meta.kind}` +
            `${name ? ` (${name})` : ""} seq=${meta.seq} len=${meta.length}` +
            (meta.unknown ? ` UNKNOWN: ${f.extra.reason}` : ""),
        );
        if (DEBUG) console.log(hexdump(f.bytes));
      });

    const pC2S = mkParser("c2s");
    const pS2C = mkParser("s2c");

    // Tujuan asli dibaca dari device dulu (async). Selama menunggu, byte dari
    // klien ditahan apa adanya di `pending` lalu dikirim utuh begitu upstream
    // siap — tidak ada byte yang diubah, hanya ditunda sesaat.
    let connected = false;
    const pending = [];
    let pendingBytes = 0;
    const MAX_PENDING = 8 * 1024 * 1024;

    const flushPending = () => {
      while (pending.length > 0 && connected && !closed) {
        const b = pending.shift();
        pendingBytes -= b.length;
        peer.write(b); // byte identik, tanpa transformasi
      }
    };

    resolveUpstream(service)
      .then((up) => {
        if (closed) return;
        peer.connect(up.port, up.host, () => {
          connected = true;
          console.log(`[${label}] terhubung ke upstream ${up.host}:${up.port}`);
          flushPending();
        });
      })
      .catch((e) => {
        console.error(`[${label}] resolusi upstream gagal: ${e.message}`);
        shutdown("gagal resolusi upstream");
      });

    // --- Client -> upstream: teruskan byte APA ADANYA, lalu catat ---
    client.on("data", (chunk) => {
      if (closed) return;
      pC2S.push(chunk); // catat dulu: pencatatan tidak boleh tergantung koneksi
      if (connected) {
        peer.write(chunk); // byte identik, tanpa transformasi
        return;
      }
      if (pendingBytes + chunk.length > MAX_PENDING) {
        console.error(
          `[${label}] antrean byte melebihi ${MAX_PENDING}B, memutus`,
        );
        shutdown("antrean upstream penuh");
        return;
      }
      pending.push(chunk);
      pendingBytes += chunk.length;
    });

    // --- Upstream -> client: teruskan byte APA ADANYA, lalu catat ---
    peer.on("data", (chunk) => {
      if (!closed) client.write(chunk); // byte identik, tanpa transformasi
      pS2C.push(chunk);
    });

    const shutdown = (why) => {
      if (closed) return;
      closed = true;
      pC2S.flush();
      pS2C.flush();
      console.log(`[${label}] koneksi ditutup (${why})`);
      client.destroy();
      peer.destroy();
    };
    client.on("close", () => shutdown("klien"));
    peer.on("close", () => shutdown("upstream"));
    client.on("error", (e) => {
      console.error(`[${label}] error klien: ${e.message}`);
      shutdown("error klien");
    });
    peer.on("error", (e) => {
      console.error(`[${label}] error upstream: ${e.message}`);
      shutdown("error upstream");
    });
  });

  server.listen(service.localPort, HOST, () => {
    console.log(
      `[relay] ${service.name} listen ${HOST}:${service.localPort} -> ${service.upstream.host}:${service.upstream.port}`,
    );
  });
  return server;
}

console.log("====================================================");
console.log("   MLBB Relay (passthrough + logging)");
console.log("   Mode     : relay — TIDAK mengubah byte sama sekali");
console.log(
  `   Capture  : ${path.relative(process.cwd(), CAPTURE_ROOT)}/<sesi>/`,
);
console.log(
  `   DEBUG    : ${DEBUG ? "aktif (hex dump)" : "mati (-v / DEBUG=1 untuk aktif)"}`,
);
console.log("====================================================");

for (const svc of AUTH_SERVICES) serve(svc);
for (const svc of ZONE_SERVICES) serve(svc);

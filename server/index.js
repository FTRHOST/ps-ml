/**
 * server/index.js — MLBB Private Server
 *
 * Entry utama server lokal:
 *   MODE=replay  node server/index.js     -> replay dari capture lokal (default)
 *   MODE=emulate DIAMOND=2626 node server/index.js
 *   MODE=relay   node relay.js            -> passthrough ke server resmi (Fase 1)
 *
 * Arsitektur:
 *   Auth  (30021/30071) : probe Cold Start, Full Login 0x70000101,
 *                         CheckUpgrade 0x70000501, GetBulletin 0x70000701.
 *   Zone  (30101/10003) : handshake 0x7000914e -> Net_Connect_SC 0x7000924e,
 *                         lalu replay s2c dari cache (opcode request + 0x100).
 *
 * Catatan protokol build 2.2.29 (terbukti dari capture 2026-11-07):
 *   - Port auth bergeser ke 30071 pada sebagian koneksi; port zone 10003.
 *     Karena itu server mendengarkan SEMUA port yang pernah dipakai klien.
 *   - Paket besar dibungkus amplop zstd: [10 00][total u16BE][zstd payload],
 *     payload = [opcode u32][seq u8][byte tambahan][0x46][varint(bodyLen-1)][body].
 *   - 0x7000a14e adalah laporan telemetri (fire-and-forget), server resmi
 *     tidak membalasnya.
 *
 * MODE=replay  : seluruh response diambil dari cache capture lokal (`captures/**`).
 *                Tidak pernah terhubung ke server resmi. Ini yang disebut "replay".
 * MODE=emulate : replay + override field khusus (mis. iDiamond -> DIAMOND).
 *                Override HANYA aktif di mode emulate (guard: relay menolak override).
 */

const net = require("net");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const sdp = require("../sdp");
const {
  HOST,
  SERVER_IP,
  buildColdStartReject,
  buildLoginAuthSC,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  buildNetConnectSC,
} = require("../auth-server");

const MODE = (process.env.MODE || "replay").toLowerCase();

/**
 * Nilai diamond: env DIAMOND > state/profile.json > 2626.
 * Profil lokal membuat nilai default bisa diubah tanpa mengedit kode.
 */
function loadProfile() {
  const file = path.join(__dirname, "..", "state", "profile.json");
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (_) {
    return {};
  }
}
const PROFILE = loadProfile();
const DIAMOND = Number(
  process.env.DIAMOND !== undefined
    ? process.env.DIAMOND
    : PROFILE.diamond || 2626,
);
const LEVEL = Number(
  process.env.LEVEL !== undefined ? process.env.LEVEL : PROFILE.level || 6,
);

/** Opcode Cmd_Role_Init_SC: field iDiamond ada di tag 11 struct CmdRoleInfo. */
const ROLE_INIT_SC = 0x7000f64e;
const DIAMOND_TAG = 11;
/** Field iLevel pada struct yang sama. */
const LEVEL_TAG = 3;

/**
 * Cmd_Role_GetInfo_SC (balasan 0x70009f4f) membawa level di level teratas
 * (bukan di dalam struct). Tanpa patch ini, level bisa kembali ke nilai capture
 * saat klien menyegarkan info role.
 */
const ROLE_INFO_SC = 0x7000a04f;

/** Cmd_Net_ServerTime_SC: tag 0 = epoch milidetik, tag 1 = offset zona waktu. */
const SERVER_TIME_SC = 0x7000a04e;
const SERVER_TIME_TAG = 0;

/** Folder bukti untuk request yang belum punya handler/cache (FR-3.3). */
const UNHANDLED_DIR = path.join(__dirname, "..", "unhandled");
/** Kunci opcode+panjang yang sudah dicatat, supaya file tidak membanjir. */
const unhandledSeen = new Set();

function recordUnhandled(opcode, seq, raw, extra = {}) {
  const key = `${hex32(opcode)}:${raw.length}`;
  if (unhandledSeen.has(key)) return;
  unhandledSeen.add(key);
  try {
    fs.mkdirSync(UNHANDLED_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
    const base = `${stamp}-${String(seq).padStart(3, "0")}-c2s-${hex32(opcode).slice(2)}`;
    fs.writeFileSync(path.join(UNHANDLED_DIR, `${base}.bin`), raw);
    fs.writeFileSync(
      path.join(UNHANDLED_DIR, `${base}.json`),
      JSON.stringify(
        {
          opcode: hex32(opcode),
          seq,
          length: raw.length,
          expected_response: extra.expected ? hex32(extra.expected) : null,
          reason: extra.reason || "cache miss",
          timestamp: Date.now(),
        },
        null,
        2,
      ),
    );
    console.log(`[unhandled] ${hex32(opcode)} -> unhandled/${base}.bin`);
  } catch (e) {
    console.log(`[unhandled] gagal menyimpan ${hex32(opcode)}: ${e.message}`);
  }
}

/** Batas frame wajar; di luar ini dianggap framing rusak. */
const MAX_FRAME = 16 * 1024 * 1024;

/**
 * Opcode yang memang tidak dibalas server resmi. Tanpa daftar ini, log akan
 * penuh "cache miss" padahal perilakunya benar.
 */
const NO_REPLY = new Set([
  0x7000a14e, // laporan client_loginstepdata (telemetri login)
]);

/**
 * Push server yang menyusul sebuah respons (bukan balasan request +0x100).
 * Contoh nyata: setelah `Cmd_Role_GetInfo_SC` (0x7000a04f) server resmi
 * mengirim daftar aktivitas `0x7000b04f`. Tanpa push ini, layar Preparation
 * berhenti di "Retrieving data" lalu kembali ke lobby.
 * Nilai: opcode request -> daftar opcode push yang diambil dari cache.
 */
const PUSH_AFTER = new Map([[0x70009f4f, [0x7000b04f]]]);

/** Port yang didengarkan (dipisah koma, lihat catatan protokol di atas). */
function parsePorts(value, fallback) {
  const raw = value === undefined || value === "" ? fallback : String(value);
  return raw
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
}
const AUTH_PORTS = parsePorts(process.env.AUTH_PORT, "30021,30071");
const ZONE_PORTS = parsePorts(process.env.ZONE_PORT, "30101,10003");

const hex32 = (n) => "0x" + (n >>> 0).toString(16);

// ---------------------------------------------------------------------------
// Amplop zstd ("probe") yang dipakai build 2.2.29
// ---------------------------------------------------------------------------
/** total u16BE bila buffer diawali penanda probe [10 00], selain itu null. */
function probeTotal(buf) {
  if (buf.length < 4 || buf[0] !== 0x10 || buf[1] !== 0x00) return null;
  return buf.readUInt16BE(2);
}

function probeUnpack(buf) {
  try {
    return zlib.zstdDecompressSync(buf.subarray(4));
  } catch (_) {
    return null;
  }
}

/** Bungkus payload (inner) menjadi amplop probe siap kirim. */
function probePack(inner) {
  const payload = zlib.zstdCompressSync(inner);
  const head = Buffer.alloc(4);
  head[0] = 0x10;
  head[1] = 0x00;
  head.writeUInt16BE(4 + payload.length, 2);
  return Buffer.concat([head, payload]);
}

/**
 * Urai isi amplop probe:
 *   [opcode u32][seq u8][byte tambahan...][0x46][varint(bodyLen-1)][body]
 * Posisi 0x46 dicari dengan validasi panjang ketat supaya tidak salah tebak.
 */
function probeParseInner(inner) {
  if (!inner || inner.length < 9) return null;
  const opcode = inner.readUInt32BE(0);
  const seq = inner[4];
  const limit = Math.min(inner.length, 16);
  for (let pos = 5; pos < limit; pos++) {
    if (inner[pos] !== 0x46) continue;
    let r;
    try {
      r = sdp.readVarUint(inner, pos + 1);
    } catch (_) {
      continue;
    }
    const bodyStart = r.next;
    const bodyLen = Number(r.val) + 1;
    if (bodyStart + bodyLen !== inner.length) continue;
    return {
      opcode,
      seq,
      headerPos: pos,
      bodyStart,
      body: inner.subarray(bodyStart),
    };
  }
  return null;
}

/** Bangun ulang isi amplop probe dengan seq/body baru (header asli dipertahankan). */
function probeBuildInner(opcode, seq, body, extra = Buffer.alloc(0)) {
  const head = Buffer.alloc(5);
  head.writeUInt32BE(opcode >>> 0, 0);
  head[4] = seq & 0xff;
  return Buffer.concat([
    head,
    extra,
    Buffer.from([0x46]),
    sdp.writeVarUint(body.length - 1),
    body,
  ]);
}

// ---------------------------------------------------------------------------
// Cache replay
// ---------------------------------------------------------------------------
/**
 * Muat frame s2c dari capture ke cache per opcode.
 * Sesi terbaru diutamakan: direktori diurutkan menurun dan entri pertama menang,
 * supaya perilaku mengikuti versi server terakhir, bukan capture lama.
 */
function loadReplayCache() {
  const cache = new Map();
  const capDir = path.join(__dirname, "..", "captures");
  let sessions = [];
  try {
    sessions = fs
      .readdirSync(capDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(capDir, d.name))
      .sort()
      .reverse();
  } catch (_) {
    return cache;
  }

  for (const session of sessions) {
    let files = [];
    try {
      files = fs.readdirSync(session);
    } catch (_) {
      continue;
    }
    for (const f of files) {
      const m = /^\d+-s2c-([0-9a-f]{8})\.(bin|zstd)$/.exec(f);
      if (!m) continue;
      const opcodeHex = "0x" + m[1];
      if (cache.has(opcodeHex)) continue; // sesi terbaru menang
      const opcode = parseInt(m[1], 16);
      let buf;
      try {
        buf = fs.readFileSync(path.join(session, f));
      } catch (_) {
        continue;
      }

      if (m[2] === "bin") {
        if (buf.length < 9 || buf.readUInt32BE(4) !== opcode) continue;
        const parsed = sdp.parseFrame(buf);
        if (!parsed) continue;
        cache.set(opcodeHex, {
          kind: "plain",
          opcode,
          raw: buf,
          envelope: parsed.envelope,
          hdr: Buffer.from(parsed.hdr),
          body: parsed.body,
        });
        continue;
      }

      // Amplop zstd
      const inner = probeUnpack(buf);
      const parsed = probeParseInner(inner);
      if (!parsed || parsed.opcode !== opcode) continue;
      cache.set(opcodeHex, {
        kind: "probe",
        opcode,
        raw: buf,
        inner,
        headerPos: parsed.headerPos,
        body: parsed.body,
      });
    }
  }
  return cache;
}

const REPLAY_CACHE = loadReplayCache();

// ---------------------------------------------------------------------------
// Patch body SDP (override diamond)
// ---------------------------------------------------------------------------
/**
 * Set field `fieldTag` pada setiap struct top-level menjadi `value`.
 * Field yang belum ada (karena nilainya 0 dan tidak diserialisasi) DISISIPKAN
 * pada urutan tag yang benar.
 */
function patchStructField(bodyBuf, fieldTag, value) {
  const nodes = sdp.decode(bodyBuf);
  const out = nodes.map((n) => {
    if (n.type !== sdp.T.STRUCT) return n;
    const fields = n.fields.map((f) => ({ ...f }));
    const idx = fields.findIndex(
      (f) =>
        f.tag === fieldTag && (f.type === sdp.T.INT || f.type === sdp.T.NEG),
    );
    if (idx >= 0) {
      fields[idx] = { ...fields[idx], type: sdp.T.INT, v: BigInt(value) };
    } else {
      const inserted = { tag: fieldTag, type: sdp.T.INT, v: BigInt(value) };
      let at = fields.findIndex((f) => f.tag > fieldTag);
      if (at < 0) at = fields.length;
      fields.splice(at, 0, inserted);
    }
    return { ...n, fields };
  });
  return sdp.encode(out);
}

/**
 * Set field `fieldTag` pada level teratas body (bukan di dalam struct) menjadi
 * `value`. Dipakai bila body tidak dibungkus struct. Field yang belum ada
 * disisipkan dengan urutan tag yang wajar.
 */
function patchTopLevelField(bodyBuf, fieldTag, value) {
  const nodes = sdp.decode(bodyBuf);
  const out = nodes.slice();
  const idx = out.findIndex(
    (n) => n.tag === fieldTag && (n.type === sdp.T.INT || n.type === sdp.T.NEG),
  );
  if (idx >= 0) {
    out[idx] = { ...out[idx], type: sdp.T.INT, v: BigInt(value) };
  } else {
    const inserted = { tag: fieldTag, type: sdp.T.INT, v: BigInt(value) };
    let at = out.findIndex((n) => n.tag > fieldTag);
    if (at < 0) at = out.length;
    out.splice(at, 0, inserted);
  }
  return sdp.encode(out);
}

/**
 * Patch satu field tanpa peduli bentuk body:
 *   - body dibungkus struct  -> patch di dalam struct (pola Cmd_Role_*)
 *   - body datar             -> patch di level teratas
 * Field yang belum ada akan disisipkan.
 */
function patchField(bodyBuf, fieldTag, value) {
  const nodes = sdp.decode(bodyBuf);
  const hasStruct = nodes.some((n) => n.type === sdp.T.STRUCT);
  return hasStruct
    ? patchStructField(bodyBuf, fieldTag, value)
    : patchTopLevelField(bodyBuf, fieldTag, value);
}

/** Render entri cache menjadi frame siap kirim dengan seq tertentu. */
function renderFrame(entry, seq, newBody) {
  if (entry.kind === "plain") {
    if (!newBody) {
      const out = Buffer.from(entry.raw);
      if (out.length > 8) out[8] = seq & 0xff;
      return out;
    }
    const hdr = Buffer.from(entry.hdr);
    if (hdr.length > 0) hdr[0] = seq & 0xff; // seq adalah byte pertama header
    return sdp.buildFrame(entry.opcode, seq, newBody, entry.envelope, hdr);
  }
  const extra = entry.inner.subarray(5, entry.headerPos);
  const inner = probeBuildInner(
    entry.opcode,
    seq,
    newBody || entry.body,
    extra,
  );
  return probePack(inner);
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------
function handleAuthOpcode(sock, opcode, seq, style, label, raw) {
  let built = null;
  if (opcode === 0x70000101) {
    console.log(`[${label}] Cmd_Login_Auth_CS -> Cmd_Login_Auth_SC`);
    built = buildLoginAuthSC(seq);
  } else if (opcode === 0x70000501) {
    console.log(
      `[${label}] Cmd_Login_CheckUpgrade_CS -> Cmd_Login_CheckUpgrade_SC`,
    );
    built = buildLoginCheckUpgradeSC(seq, `${SERVER_IP}:${ZONE_PORTS[0]}`);
  } else if (opcode === 0x70000701) {
    console.log(
      `[${label}] Cmd_Login_GetBulletin_CS -> Cmd_Login_GetBulletin_SC`,
    );
    built = buildLoginGetBulletinSC(seq);
  } else {
    console.log(
      `[${label}] opcode ${hex32(opcode)} tidak ditangani -> dicatat`,
    );
    if (raw)
      recordUnhandled(opcode, seq, raw, { reason: "auth tanpa handler" });
    return;
  }

  if (style === "probe") {
    const parsed = sdp.parseFrame(built);
    const inner = probeBuildInner(parsed.opcode, seq, parsed.body);
    sock.write(probePack(inner));
  } else {
    sock.write(built);
  }
}

function handleZoneOpcode(sock, opcode, seq, label, raw) {
  if (opcode === 0x7000914e) {
    // Balasan resmi berisi sSessionKey base64 68 karakter. Utamakan frame asli
    // dari capture supaya kunci sesi yang dipakai klien benar-benar valid.
    const handshake = REPLAY_CACHE.get(hex32(0x7000924e));
    if (handshake) {
      console.log(
        `[${label}] Handshake Cmd_Net_Connect_CS -> Cmd_Net_Connect_SC (cache)`,
      );
      sock.write(renderFrame(handshake, seq));
    } else {
      console.log(
        `[${label}] Handshake Cmd_Net_Connect_CS -> Cmd_Net_Connect_SC (builder)`,
      );
      sock.write(buildNetConnectSC(seq));
    }
    return;
  }

  if (NO_REPLY.has(opcode >>> 0)) return; // fire-and-forget

  const respOpcode = (opcode + 0x100) >>> 0;
  const entry = REPLAY_CACHE.get(hex32(respOpcode));
  if (!entry) {
    console.log(
      `[${label}] cache miss ${hex32(opcode)} -> ${hex32(respOpcode)}`,
    );
    if (raw) recordUnhandled(opcode, seq, raw, { expected: respOpcode });
    return;
  }

  let body;
  if (respOpcode === SERVER_TIME_SC) {
    // Waktu server harus segar; memakai nilai capture membuat selisih jam
    // terhadap klien makin besar setiap sesi (FR-3.2).
    body = patchStructField(entry.body, SERVER_TIME_TAG, Date.now());
  }
  if (MODE === "emulate" && respOpcode === ROLE_INIT_SC) {
    body = patchField(body || entry.body, DIAMOND_TAG, DIAMOND);
    body = patchField(body, LEVEL_TAG, LEVEL);
    console.log(
      `[${label}] override iDiamond=${DIAMOND} iLevel=${LEVEL} pada Cmd_Role_Init_SC`,
    );
  }
  if (MODE === "emulate" && respOpcode === ROLE_INFO_SC) {
    // Klien menyegarkan info role lewat opcode ini; tanpa patch, level kembali
    // ke nilai capture lama.
    body = patchField(body || entry.body, LEVEL_TAG, LEVEL);
    console.log(`[${label}] override iLevel=${LEVEL} pada Cmd_Role_GetInfo_SC`);
  }
  sock.write(renderFrame(entry, seq, body));

  // Push lanjutan (bukan balasan request +0x100). Dikirim setelah respons utama
  // supaya urutannya menyerupai server resmi.
  const pushes = PUSH_AFTER.get(opcode >>> 0);
  if (pushes) {
    for (const pushOpcode of pushes) {
      const pushEntry = REPLAY_CACHE.get(hex32(pushOpcode));
      if (!pushEntry) continue;
      console.log(
        `[${label}] push ${hex32(pushOpcode)} setelah ${hex32(opcode)}`,
      );
      setTimeout(() => {
        if (!sock.destroyed) sock.write(renderFrame(pushEntry, seq));
      }, 80);
    }
  }
}

/** Parser stream generik: mendukung frame biasa maupun amplop probe. */
function makeZoneHandler(sock, label) {
  let buf = Buffer.alloc(0);
  sock.on("data", (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (buf.length < 4) break;
      const total = probeTotal(buf);
      if (total !== null) {
        if (total < 4) {
          console.log(`[${label}] panjang probe tidak masuk akal (${total})`);
          buf = Buffer.alloc(0);
          break;
        }
        if (buf.length < total) break;
        const packet = buf.subarray(0, total);
        buf = buf.subarray(total);
        const parsed = probeParseInner(probeUnpack(packet));
        if (!parsed) {
          console.log(`[${label}] probe tidak bisa diurai -> diabaikan`);
          continue;
        }
        console.log(
          `[${label}] RECV ${hex32(parsed.opcode)} seq=${parsed.seq} len=${total} (zstd)`,
        );
        handleZoneOpcode(sock, parsed.opcode, parsed.seq, label, packet);
        continue;
      }

      const len = buf.readUInt32BE(0);
      if (len < 9 || len > MAX_FRAME) {
        console.log(`[${label}] data non-protokol (len=${len}) -> dibuang`);
        buf = Buffer.alloc(0);
        break;
      }
      if (buf.length < len) break;
      const packet = buf.subarray(0, len);
      buf = buf.subarray(len);
      const opcode = packet.readUInt32BE(4);
      const seq = packet.length > 8 ? packet[8] : 0x01;
      console.log(`[${label}] RECV ${hex32(opcode)} seq=${seq} len=${len}`);
      handleZoneOpcode(sock, opcode, seq, label, packet);
    }
  });
}

function makeAuthHandler(sock, label) {
  let buf = Buffer.alloc(0);
  sock.on("data", (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (buf.length < 4) break;
      const total = probeTotal(buf);
      if (total !== null) {
        if (total < 4) {
          buf = Buffer.alloc(0);
          break;
        }
        if (buf.length < total) break;
        const packet = buf.subarray(0, total);
        buf = buf.subarray(total);
        const inner = probeUnpack(packet);
        const parsed = inner ? probeParseInner(inner) : null;
        if (!parsed) {
          // Non-zstd ATAU zstd valid tapi tanpa header 0x46 -> Cold Start probe.
          console.log(
            `[${label}] Cold Start probe (${total}B, inner=${inner ? inner.toString("hex") : "non-zstd"}) -> tolak -45 (Session Expired)`,
          );
          sock.write(buildColdStartReject(0x01), () => sock.end());
          return;
        }
        console.log(
          `[${label}] RECV ${hex32(parsed.opcode)} seq=${parsed.seq} len=${total} (zstd)`,
        );
        handleAuthOpcode(
          sock,
          parsed.opcode,
          parsed.seq,
          "probe",
          label,
          packet,
        );
        continue;
      }

      const len = buf.readUInt32BE(0);
      if (len < 9 || len > MAX_FRAME) {
        // Kemungkinan laporan teks (client_loginstepdata); tidak butuh balasan.
        buf = Buffer.alloc(0);
        break;
      }
      if (buf.length < len) break;
      const packet = buf.subarray(0, len);
      buf = buf.subarray(len);
      const opcode = packet.readUInt32BE(4);
      const seq = packet.length > 8 ? packet[8] : 0x01;
      console.log(`[${label}] RECV ${hex32(opcode)} seq=${seq} len=${len}`);
      handleAuthOpcode(sock, opcode, seq, "plain", label, packet);
    }
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function listen(port, name, handler) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      const from = `${sock.remoteAddress}:${sock.remotePort}`;
      console.log(`\n[${name}:${port}] klien terhubung dari ${from}`);
      handler(sock, `${name}:${port}`);
      sock.on("close", () => console.log(`[${name}:${port}] klien terputus`));
      sock.on("error", (e) =>
        console.log(`[${name}:${port}] error: ${e.message}`),
      );
    });
    server.once("error", reject);
    server.listen(port, HOST, () => resolve(server));
  });
}

async function main() {
  if (MODE === "relay") {
    console.log(
      "[SERVER] MODE=relay -> gunakan relay.js (passthrough). Override diamond DITOLAK di mode ini.",
    );
    process.exit(1);
  }
  if (MODE !== "replay" && MODE !== "emulate") {
    console.error(`[SERVER] MODE tidak dikenal: ${MODE}. Pakai replay|emulate`);
    process.exit(1);
  }

  console.log(`[SERVER] cache replay: ${REPLAY_CACHE.size} opcode`);
  if (MODE === "emulate") {
    console.log(
      `[SERVER] MODE=emulate -> replay + override diamond=${DIAMOND} level=${LEVEL}`,
    );
  } else {
    console.log(
      "[SERVER] MODE=replay -> replay dari capture lokal (tanpa override diamond/level)",
    );
  }

  for (const port of AUTH_PORTS) await listen(port, "AUTH", makeAuthHandler);
  for (const port of ZONE_PORTS) await listen(port, "ZONE", makeZoneHandler);

  console.log("====================================================");
  console.log("   MLBB Standalone Server Aktif!");
  console.log(`   Port Auth : ${AUTH_PORTS.join(", ")}`);
  console.log(`   Port Zone : ${ZONE_PORTS.join(", ")}`);
  console.log(`   Server IP : ${SERVER_IP}`);
  console.log("   ColdStart : Handled (-45 Session Expired)");
  console.log("   CDN Mode  : Official Moonton CDN");
  console.log("====================================================");
  console.log(
    `[SERVER] Server index aktif. MODE=${MODE} DIAMOND=${DIAMOND} LEVEL=${LEVEL}`,
  );
}

if (require.main === module) {
  main().catch((e) => {
    console.error("[SERVER] gagal start:", e.message);
    process.exit(1);
  });
}

// Diekspor untuk uji offline (tools/verify-diamond.js), bukan API publik.
module.exports = {
  loadReplayCache,
  patchStructField,
  patchTopLevelField,
  patchField,
  renderFrame,
  probeUnpack,
  probeParseInner,
  probePack,
  probeBuildInner,
  REPLAY_CACHE,
  ROLE_INIT_SC,
  DIAMOND_TAG,
  LEVEL_TAG,
  ROLE_INFO_SC,
  DIAMOND,
  LEVEL,
};

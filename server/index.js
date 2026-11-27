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
  Cmd_Login_Auth_CS,
  buildLoginGetZoneSC,
  Cmd_Login_GetZone_CS,
  findAuthAccount,
  findAuthAccountById,
  createAuthAccount,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  buildNetConnectSC,
  buildRoomEnterSCBody,
  buildRoomGetInfoSCBody,
  parseRoomEnterCS,
  AUTH_UID,
} = require("../auth-server");

const MODE = (process.env.MODE || "replay").toLowerCase();

/** Akun terakhir yang login (untuk patch Role_Init di zone). */
let CURRENT_ACCOUNT = null;

// Template auth standalone (disematkan, tidak bergantung pada captures/).
// Sumber: capture resmi terbaru; field dinamis disesuaikan saat render.
const AUTH_SC_TEMPLATE = Buffer.from(
  "EAACsii1L/1grgIlFQCWa5tEIIvqAQAMEFaQEiIwADBAEAS2FEAo2OtT2CjlbcjyZWWzWzrymmUOz/B6hueb+fjM7Xn5JGF5IfW/5Su4p4QbO20BogOUAIAAfwAaxjcB4YAk4SiBRWAQERIJDR0uZMA+Eh5WbKJbaCfdlZso7BYpu9WhXE6lCQVJMqFVwECBw4QAHJAElLkL1uQL1vKFy+QB4QuD4HLWsRKbj4SHr6FxbjTZEwpJa6tLLb2kcj84C9jCWDAcDx4tr+VFqV37S7/jdUWXi9r0HOkw0MytxS1dNXq71AZnswKw4MEwycMa+vNW5ZrjEHye2b3OOE5/virbvbKoWeDzMt29L/nPP6pnN+/QeJugKprmz9vek7f7t6z+vO2oSr8umfF5mQyDtwxnmod8zpJel/yTZE+16f+qsUaBuX1XXd5k3b6WOss0jC9Cpfvfqr6sNKicu9Wr6/9ZeeDxc6s75eV3Pcu/1gIvL8sZZzhbfB4fQVO0XUk8RU8qenrRlis+L7OtN03+9ZYFfBmXddjFVf25+UksN7m8aMsEvtyyvPU+f3df07erfsuWzzvV/bp+pbPqUfbzEM2yq97ygc/LZvd6d5/qLU98nmbxef6vWvVou011p6kv+dfovvi8TL/fl5r3tt1krxe2gGKTpWZzbG5kRsPgDO8wWMWZGLLjHbdpSA3FAGmDYqVExGzE42mEOU4iBnFIIiVr1EDpyFVyRitPmlqFwpRrHBnhETVqHumIQeGGA5PLAzWGWPRRcZj6PEEWeQoJOwjIORJX3YYpzMCljw8YYo2QnJmiageVCoEgSAQ5OiIoemzAzaeEcEHCNrwqEgQTADwKdfgAcFlnAG3Pw6rNxMCWrjU4WfvIkE+7QPPV46a2DQAri1aJBCBSKiLQKISo3aLQ",
  "base64",
);
const CHECKUPGRADE_SC_TEMPLATE = Buffer.from(
  "EAADkyi1L/1gxgktHABW7JREAJObAKMpRbaqUL0KULSmYKXe6OxNelX1/iKJsF67ZLdBG4nkyomfOB22t45zR622mFJKKaX/aRNOR0vYaZaJhOeGlzaFAIYAgADfpzvNsqHTqFTcmd5KIvyMLz3a+XH+h+KAKnUlDVHqzkTTHvehUCBQG3N0jQNQ6zZpc3FzpZFniiYvU6CVUECupMOtYeD3aWyfvBDETF4WN0fyPFJMae7DsBPwC0MWT4pXDTzW+R7nx48fsmBKl/OEzmjlx5cf3TrJ50GHj48jk1JVmo8v1MNIqEMv6ddLaLJJ2rb4+jAg5BEQOulQt2jQBUGAkHZN0n0z1vSsWcuu3Bt1/0xr1nPPbDq1WttXtuHXNlp1lvHUltadMZ2bHVX9G9Y3z5rlajUKIiGQzYTOK4Gn3ZJCBXQJNe7rYCxZqD8RuE8mTUp5GEgdyktFzhQ7LTNl0Bh2UsVIwAIPevs3s3gpM16R/ee9rsLSXIztlTLLWNbvfBljXQD3iojTmaci2pnmvr1iYSTlpVd5rVsUlgb01cdxlSc4/49pNWFJfw7+6bXmEr8Z4ZPK9yzCusw3hN/8l2LpV8SgQojng6kAbEBYs+Px53sIyKsPlY6xxfi66KW0bTxfCYmoEzAwlQGR0abl15vvtkd6G21Vq9jt1a5lq+3UDhAIaWKQmNnBEelheVzv0z61dMZKgOX8KnVY/l8C+o6DfGy+9F7PQa+c+ToOWW/I65/627Ckbyi+2HMN6x1fS0Ne2XGm8vOMC0RlUK/Xq8PA1DP9F9OFRQtI7FJ6/RbWuzsNgImoAUnF0BANAhAQkCAoAMAigKLqARKAMUiWpTiABRipEGAKgQCCCSAAgAAGBgaAHLZLSbUGAlENzSjiyHmkAkMebI545rc/57xj7vO/SqAYkvwZH0ceBj6xoSDR9Z2BSJzpHXoK5xURRXiJehSS8XTkjz9Uyh1d+vvO0xW2PEh1UUyehuopPLx5XmKElW/1UZUgJAz5MlwUAASaoQ+Sysiagw7kBoEOYmRPE5FBj4tF+fw/SbI0KBKsixRgPh7zy1ryBARUTPuejmchyAOwnd04DF4kqChiNrlEqUs/yB43im5Z3dE6tx4+cvzNtZm290kJirhSGS2RZWyMO0CusgF8J2EWBfG33FSz3m5Srd3NR247frJvD3QokPLBtfMgPJjPOgaK4KvJI0IU37ED",
  "base64",
);
const ROLE_INIT_SC_TEMPLATE = Buffer.from(
  "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",
  "base64",
);

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

/** State role lokal (gitignored); dipakai untuk identitas tambahan. */
function loadRoleState() {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "state", "role.json"), "utf8"),
    );
  } catch (_) {
    return {};
  }
}
const ROLE = loadRoleState();

const DIAMOND = Number(
  process.env.DIAMOND !== undefined
    ? process.env.DIAMOND
    : ROLE.diamond ?? PROFILE.diamond ?? 2626,
);
const LEVEL = Number(
  process.env.LEVEL !== undefined
    ? process.env.LEVEL
    : ROLE.level ?? PROFILE.level ?? 6,
);

/**
 * Nama role yang dipakai semua response lokal berbasis capture. Template resmi
 * masih menyimpan `Fathir_Qepo`, jadi field sName/iUid harus ditimpa supaya
 * layar menampilkan identitas lokal. Bisa diganti lewat env ROLE_NAME.
 */
const ROLE_NAME = process.env.ROLE_NAME || ROLE.name || "petwir0x";

/** Uid role yang dipakai capture; uid kecil (1) dianggap role baru oleh klien. */
const ROLE_UID = Number(process.env.ROLE_UID || ROLE.uid || 332108113);
const ROLE_FACE = Number(process.env.ROLE_FACE || ROLE.faceId || 101);
const ROLE_NATIONALITY = Number(
  process.env.ROLE_NATIONALITY || ROLE.nationality || 14,
);
const ROLE_RANK = Number(process.env.ROLE_RANK || ROLE.rankLevel || 95);
const ROLE_BORDER = Number(process.env.ROLE_BORDER || ROLE.faceBorderId || 127);
const ROLE_SVR_ID = Number(
  process.env.ROLE_SVR_ID || ROLE.serverId || ROLE.zoneId || 9218,
);
/**
 * Uid yang dikirim di Cmd_Login_Auth_SC. Default mengikuti ROLE_UID supaya
 * SystemData.m_uiID klien tidak 0 (Preparation diblokir bila 0).
 */
const AUTH_UID_VALUE =
  AUTH_UID !== null ? Number(AUTH_UID) : Number(process.env.ROLE_UID || ROLE_UID);

/** Skin hero 18 (Layla) yang sedang dipakai; diubah oleh Cmd_Item_Set_CurSkin_CS. */
let CURRENT_SKIN_LAYLA = 1188;

/**
 * Override identitas hanya untuk paket yang dilayani lokal (replay). Mode relay
 * murni tidak mengubah byte; hybrid hanya meneruskan opcode yang TIDAK ada di
 * cache, sehingga patch di sini tidak menyentuh trafik server resmi.
 */
const NAME_OVERRIDE = MODE === "emulate" || MODE === "hybrid";
/** Handler emulasi tambahan hanya aktif untuk paket yang dilayani lokal. */
const EMULATE = MODE === "emulate";

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
const ACCOUNT_GET_SC = 0x7000e04f;

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
const ZONE_PORTS = parsePorts(process.env.ZONE_PORT, "30101,10003,30103");

function parseAddr(value, fallback) {
  const s = String(value || fallback);
  const i = s.lastIndexOf(":");
  if (i < 0) return { host: s, port: 30000 };
  return { host: s.slice(0, i), port: Number(s.slice(i + 1)) };
}
const AUTH_UPSTREAM = parseAddr(process.env.AUTH_UPSTREAM, "login.ml.youngjoygame.com:30021");
const ZONE_UPSTREAM = parseAddr(process.env.ZONE_UPSTREAM, "161.202.206.34:30103");

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
    if (inner[pos] !== 0x45 && inner[pos] !== 0x46) continue;
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

/**
 * Patch biner terarah untuk Cmd_Role_Init_SC (tag 3 level, tag 11 diamond).
 * Tidak bergantung pada decode penuh; field awal yang valid cukup untuk
 * menemukan titik sisip (setelah tag 10) dan menimpa tag 3.
 */
function patchRoleInitBinary(bodyBuf, diamond, level, accountId, name) {
  const T = sdp.T;
  const fields = [];
  let pos = 1; // lewati header struct (0x70)
  while (pos < bodyBuf.length - 1) {
    if (bodyBuf[pos] === 0x80) break; // StructEnd
    let node, nx;
    try {
      [node, nx] = sdp.decodeNode(bodyBuf, pos);
    } catch (_) {
      fields.push({ tag: null, start: pos, end: bodyBuf.length - 1, raw: bodyBuf.subarray(pos, bodyBuf.length - 1) });
      pos = bodyBuf.length - 1;
      break;
    }
    fields.push({ tag: node.tag, start: pos, end: nx });
    pos = nx;
  }

  const segments = [];
  let hasDiamond = false;
  for (const f of fields) {
    if (f.tag === 0 && accountId) {
      segments.push(sdp.encodeNode({ tag: 0, type: T.INT, v: BigInt(accountId) }));
    } else if (f.tag === 1 && name) {
      segments.push(sdp.encodeNode({ tag: 1, type: T.STRING, raw: Buffer.from(name, "utf8") }));
    } else if (f.tag === 3) {
      segments.push(sdp.encodeNode({ tag: 3, type: T.INT, v: BigInt(level) }));
    } else if (f.tag === 11) {
      hasDiamond = true;
      segments.push(sdp.encodeNode({ tag: 11, type: T.INT, v: BigInt(diamond) }));
    } else if (f.raw) {
      segments.push(f.raw);
    } else {
      segments.push(bodyBuf.subarray(f.start, f.end));
    }
  }

  if (!hasDiamond) {
    const diamondNode = sdp.encodeNode({ tag: 11, type: T.INT, v: BigInt(diamond) });
    let idx = -1;
    for (let i = 0; i < fields.length; i++) {
      if (fields[i].tag !== null && fields[i].tag < 11) idx = i;
    }
    if (idx >= 0) segments.splice(idx + 1, 0, diamondNode);
    else segments.unshift(diamondNode);
  }

  return Buffer.concat([Buffer.from([0x70]), ...segments, Buffer.from([0x80])]);
}

/**
 * Timpa semua string SDP yang masih memakai nama akun capture lama.
 * Patch khusus (Role_Init/Role_Info/Account_Get) sudah menangani opcode utama,
 * tetapi capture lain (Battle_GetBattleData, d666, dab8, feb8, fcb8, ...)
 * juga menyimpan `Fathir_Qepo` dan bisa tampil di panel lain. Patch generik ini
 * dijalankan terakhir supaya tidak ada nama lama yang lolos ke klien.
 */
const LEGACY_ROLE_NAME = Buffer.from("Fathir_Qepo", "utf8");

function patchLegacyRoleName(bodyBuf, name) {
  if (!bodyBuf || !name || !bodyBuf.includes(LEGACY_ROLE_NAME)) return bodyBuf;
  try {
    const replace = (n) => {
      if (n.type === sdp.T.STRING) {
        if (n.raw.includes(LEGACY_ROLE_NAME)) {
          return { ...n, raw: Buffer.from(n.raw.toString("utf8").replace(/Fathir_Qepo/g, name), "utf8") };
        }
        return n;
      }
      if (n.type === sdp.T.STRUCT) {
        return { ...n, fields: n.fields.map(replace) };
      }
      if (n.type === sdp.T.LIST) {
        return { ...n, items: n.items.map(replace) };
      }
      if (n.type === sdp.T.MAP) {
        return {
          ...n,
          entries: n.entries.map(([k, v]) => [replace(k), replace(v)]),
        };
      }
      return n;
    };
    return sdp.encode(sdp.decode(bodyBuf).map(replace));
  } catch (_) {
    return bodyBuf;
  }
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
// Helper untuk request CS dan balasan SC buatan
// ---------------------------------------------------------------------------
/** Ambil body SDP dari frame CS (probe maupun plain). */
function extractCsBody(raw) {
  if (probeTotal(raw) !== null) {
    const inner = probeUnpack(raw);
    const parsed = inner ? probeParseInner(inner) : null;
    return parsed ? parsed.body : null;
  }
  try {
    return sdp.parseFrame(raw).body;
  } catch (_) {
    return null;
  }
}

/** Body SC tanpa field: root struct + StructEnd penutup. */
const EMPTY_SC_BODY = Buffer.from([0x70, 0x80, 0x80]);

/**
 * Byte header antara seq dan penanda arah (0x45/0x46). Server resmi menyalin
 * ID pesan ini dari request ke response, jadi balasan buatan wajib memakainya.
 */
function requestHeaderExtra(raw) {
  if (!raw) return Buffer.alloc(0);
  const total = probeTotal(raw);
  if (total !== null) {
    const inner = probeUnpack(raw);
    const parsed = inner ? probeParseInner(inner) : null;
    return parsed ? inner.subarray(5, parsed.headerPos) : Buffer.alloc(0);
  }
  if (raw.length < 9) return Buffer.alloc(0);
  const len = raw.readUInt32BE(0);
  for (let k = 1; k <= 3; k++) {
    let pos = 8;
    try {
      for (let i = 0; i < k; i++) pos = sdp.readVarUint(raw, pos).next;
    } catch (_) {
      break;
    }
    if (pos < len && (raw[pos] === 0x45 || raw[pos] === 0x46)) {
      let r;
      try {
        r = sdp.readVarUint(raw, pos + 1);
      } catch (_) {
        continue;
      }
      if (r.next + Number(r.val) + 1 === len) return raw.subarray(9, pos);
    }
  }
  return Buffer.alloc(0);
}

/** Bangun frame SC plain dengan header (ID pesan) dari request. */
function buildPlainSCFrame(opcode, seq, body, extra) {
  const hdr = Buffer.concat([
    Buffer.from([seq & 0xff]),
    extra || Buffer.alloc(0),
    Buffer.from([0x46]),
    sdp.writeVarUint(body.length - 1),
  ]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(8 + hdr.length + body.length, 0);
  const op = Buffer.alloc(4);
  op.writeUInt32BE(opcode >>> 0, 0);
  return Buffer.concat([len, op, hdr, body]);
}

/** Kirim balasan SC dengan amplop/ID pesan yang sama seperti request. */
function sendZoneReply(sock, respOpcode, seq, raw, body) {
  const viaProbe = probeTotal(raw) !== null;
  const extra = requestHeaderExtra(raw);
  sock.write(
    viaProbe
      ? probePack(probeBuildInner(respOpcode, seq, body, extra))
      : buildPlainSCFrame(respOpcode, seq, body, extra),
  );
}

/** Profil role lokal untuk builder room/battle data. */
function currentRoleProfile() {
  return {
    uid: BigInt(ROLE_UID),
    svrId: ROLE_SVR_ID,
    zoneId: ROLE_SVR_ID,
    name: ROLE_NAME,
    level: LEVEL,
    faceId: ROLE_FACE,
    nationality: ROLE_NATIONALITY,
    rankLevel: ROLE_RANK,
    faceBorderId: ROLE_BORDER,
  };
}

/** Set field int pada array field SDP (disisipkan bila belum ada). */
function setSdpInt(fields, tag, value) {
  if (value === undefined || value === null) return;
  const v = BigInt(value);
  const idx = fields.findIndex(
    (f) =>
      f.tag === tag && (f.type === sdp.T.INT || f.type === sdp.T.NEG),
  );
  if (idx >= 0) {
    fields[idx] = {
      ...fields[idx],
      type: v < 0n ? sdp.T.NEG : sdp.T.INT,
      v,
    };
    return;
  }
  const at = fields.findIndex((f) => f.tag > tag);
  fields.splice(at < 0 ? fields.length : at, 0, {
    tag,
    type: v < 0n ? sdp.T.NEG : sdp.T.INT,
    v,
  });
}

/** Set field string pada array field SDP (disisipkan bila belum ada). */
function setSdpString(fields, tag, value) {
  if (value === undefined || value === null) return;
  const raw = Buffer.from(String(value), "utf8");
  const idx = fields.findIndex((f) => f.tag === tag && f.type === sdp.T.STRING);
  if (idx >= 0) {
    fields[idx] = { ...fields[idx], raw };
    return;
  }
  const at = fields.findIndex((f) => f.tag > tag);
  fields.splice(at < 0 ? fields.length : at, 0, {
    tag,
    type: sdp.T.STRING,
    raw,
  });
}

/**
 * Patch Cmd_Login_Auth_SC supaya klien tidak membuka Create Character.
 * vSimpleRoleInfo (tag 20) dari capture punya bChangeName=1; klien memaksa
 * ganti nama worldwide bila field ini benar.
 */
function patchAuthSimpleRoleInfo(bodyBuf) {
  const nodes = sdp.decode(bodyBuf);
  const out = nodes.map((n) => {
    if (n.type !== sdp.T.STRUCT) return n;
    const fields = n.fields.map((f) => ({ ...f }));
    const roleList = fields.find(
      (f) => f.tag === 20 && f.type === sdp.T.LIST,
    );
    if (roleList) {
      const items = roleList.items.map((it) => {
        if (it.type !== sdp.T.STRUCT) return it;
        const fs = it.fields.map((f) => ({ ...f }));
        setSdpInt(fs, 0, ROLE_SVR_ID);
        setSdpInt(fs, 2, ROLE_NATIONALITY);
        setSdpInt(fs, 3, 0); // bChangeName
        setSdpInt(fs, 4, ROLE_NATIONALITY);
        setSdpInt(fs, 5, LEVEL);
        setSdpString(fs, 7, "ID");
        return { ...it, fields: fs };
      });
      fields[fields.indexOf(roleList)] = { ...roleList, items };
    }
    setSdpString(fields, 8, ROLE_NAME);
    return { ...n, fields };
  });
  return sdp.encode(out);
}

/**
 * Patch Cmd_Hero_GetList_SC: hero 18 memakai skin lokal, hero 25 dimiliki,
 * skin 1188/1189 ditandai dimiliki supaya bisa dipilih/dibeli lewat UI.
 */
function patchCmdHeroGetListBody(bodyBuf) {
  const nodes = sdp.decode(bodyBuf);
  const root = nodes.find((n) => n.type === sdp.T.STRUCT);
  if (!root) throw new Error("root struct tidak ditemukan");

  let heroListField = root.fields.find(
    (f) => f.tag === 0 && f.type === sdp.T.LIST,
  );
  if (!heroListField) {
    heroListField = { tag: 0, type: sdp.T.LIST, items: [] };
    root.fields.push(heroListField);
  }
  const heroList = heroListField.items;
  const findHero = (id) =>
    heroList.find((it) => {
      const f = it.fields && it.fields.find((x) => x.tag === 0);
      return f && Number(f.v) === id;
    });

  const layla = findHero(18);
  if (layla) {
    setSdpInt(layla.fields, 1, CURRENT_SKIN_LAYLA);
  } else {
    heroList.push(
      sdp.node.struct(0, [
        sdp.node.int(0, 18),
        sdp.node.int(1, CURRENT_SKIN_LAYLA),
      ]),
    );
  }
  if (!findHero(25)) {
    heroList.push(
      sdp.node.struct(0, [sdp.node.int(0, 25), sdp.node.int(1, 0)]),
    );
  }

  let skinListField = root.fields.find(
    (f) => f.tag === 1 && f.type === sdp.T.LIST,
  );
  if (!skinListField) {
    skinListField = { tag: 1, type: sdp.T.LIST, items: [] };
    root.fields.push(skinListField);
  }
  const skinList = skinListField.items;
  for (const skinId of [1188, 1189, 102512]) {
    const owned = skinList.some((it) => {
      const f = it.fields && it.fields.find((x) => x.tag === 0);
      return f && Number(f.v) === skinId;
    });
    if (!owned) {
      skinList.push(
        sdp.node.struct(0, [
          sdp.node.int(0, skinId),
          sdp.node.int(1, 0),
          sdp.node.int(2, 1),
        ]),
      );
    }
  }
  root.fields.sort((a, b) => a.tag - b.tag);
  return sdp.encode(nodes);
}

/**
 * Patch Cmd_Battle_GetBattleData_SC agar cache klien (key = uid) cocok dengan
 * role lokal. Tanpa ini Preparation menggantung di "Retrieving data".
 */
function patchCmdBattleGetBattleDataBody(bodyBuf, info) {
  const nodes = sdp.decode(bodyBuf);
  const root = nodes.find((n) => n.type === sdp.T.STRUCT);
  if (!root) throw new Error("root struct tidak ditemukan");
  setSdpInt(root.fields, 17, info.uid);
  setSdpInt(root.fields, 18, info.svrId);
  const base = root.fields.find(
    (n) => n.tag === 19 && n.type === sdp.T.STRUCT,
  );
  if (base) {
    setSdpInt(base.fields, 0, info.uid);
    setSdpInt(base.fields, 1, info.svrId);
    setSdpString(base.fields, 2, info.name);
    setSdpInt(base.fields, 3, info.level);
    setSdpInt(base.fields, 4, info.faceId);
  }
  return sdp.encode(nodes);
}

/** Fallback Cmd_Battle_GetBattleData_SC bila cache tidak tersedia. */
function buildCmdBattleGetBattleDataSCBody(info) {
  const fields = [];
  for (let tag = 0; tag <= 16; tag++) fields.push(sdp.node.int(tag, 0));
  const uid = BigInt(info.uid ?? 0);
  const svr = BigInt(info.svrId ?? 0);
  fields.push(sdp.node.int(17, uid));
  fields.push(sdp.node.int(18, svr));
  fields.push(
    sdp.node.struct(19, [
      sdp.node.int(0, uid),
      sdp.node.int(1, svr),
      sdp.node.str(2, info.name ?? ""),
      sdp.node.int(3, info.level ?? 0),
      sdp.node.int(4, info.faceId ?? 101),
    ]),
  );
  fields.push(sdp.node.list(21, []));
  fields.push(sdp.node.list(22, []));
  return sdp.buildBody(fields);
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------
function handleAuthOpcode(sock, opcode, seq, style, label, raw) {
  const respOpcode = (opcode + 0x100) >>> 0;

  // Template standalone untuk auth (disematkan, tidak bergantung pada captures/).
  // Diambil dari capture resmi, lalu field dinamis disesuaikan saat render.
  let templateBuf = null;
  if (opcode === 0x70000101) templateBuf = AUTH_SC_TEMPLATE;
  else if (opcode === 0x70000501) templateBuf = CHECKUPGRADE_SC_TEMPLATE;

  if (templateBuf) {
    const inner = probeUnpack(templateBuf);
    const parsed = probeParseInner(inner);
    const entry = {
      kind: "probe",
      opcode: parsed.opcode,
      raw: templateBuf,
      inner,
      headerPos: parsed.headerPos,
      body: parsed.body,
    };
    console.log(
      `[${label}] ${hex32(opcode)} -> ${hex32(respOpcode)} (template standalone)`,
    );
    let body = null;
    if (respOpcode === 0x70000201) {
      // iAccountId (tag 0) diisi dari logika DB (find/create account),
      // bukan hardcode, supaya sesuai akun yang login.
      let accountId = 1;
      let sessionKey = null;
      let stZone = null;
      try {
        let csBody = null;
        if (style === "probe") {
          const innerReq = probeUnpack(raw);
          const parsedReq = probeParseInner(innerReq);
          csBody = parsedReq ? parsedReq.body : null;
        } else {
          csBody = sdp.parseFrame(raw).body;
        }
        const cs = Cmd_Login_Auth_CS.fromSdpBody(csBody);
        let account = findAuthAccount(cs);
        if (!account) {
          console.log(`[AUTH] akun baru: "${cs.sAccountName}" (tidak ditemukan di DB)`);
          account = createAuthAccount(cs);
        } else {
          console.log(`[AUTH] akun ditemukan: id=${account.iAccountId} name="${cs.sAccountName}"`);
        }
        accountId = Number(account.iAccountId || 1);
        sessionKey = account.sSessionKey || null;
        stZone = account.stZone || null;
        CURRENT_ACCOUNT = account;
      } catch (_) {
        accountId = 1;
      }
      body = patchStructField(entry.body, 0, AUTH_UID_VALUE);
      if (sessionKey) {
        // Patch sSessionKey (tag 1) agar sesuai DB, seperti commit c32b3c0.
        const nodes = sdp.decode(body);
        const out = nodes.map((n) => {
          if (n.type !== sdp.T.STRUCT) return n;
          const fields = n.fields.map((f) => {
            if (f.tag === 1 && f.type === sdp.T.STRING) {
              return { ...f, raw: Buffer.from(sessionKey, "utf8") };
            }
            return { ...f };
          });
          return { ...n, fields };
        });
        body = sdp.encode(out);
      }
      body = patchStructField(body, 10, Date.now());
      // Capture auth tidak menyertakan bNewAccount, sehingga klien menganggap
      // akun baru dan membuka UI Create Character. Tandai sebagai akun lama
      // agar langsung masuk lobby dengan role dari replay.
      body = patchStructField(body, 12, 0);
      body = patchAuthSimpleRoleInfo(body);
      console.log(
        `[AUTH] override uid=${AUTH_UID_VALUE} bNewAccount=0 bChangeName=0 level=${LEVEL} pada Cmd_Login_Auth_SC`,
      );
    } else if (respOpcode === 0x70000601) {
      try {
        const nodes = sdp.decode(entry.body);
        const out = nodes.map((n) => {
          if (n.type !== sdp.T.STRUCT) return n;
          const fields = n.fields.map((f) => {
            if (f.tag === 1 && f.type === sdp.T.STRING) {
              return { ...f, raw: Buffer.from(`${SERVER_IP}:${ZONE_PORTS[0]}`, "utf8") };
            }
            if (f.tag === 2 && f.type === sdp.T.STRING) {
              return {
                ...f,
                raw: Buffer.from(
                  process.env.CLIENT_VERSION || "2.2.30.1256.1",
                  "utf8",
                ),
              };
            }
            if (f.tag === 13 && f.type === sdp.T.STRING) {
              return { ...f, raw: Buffer.from(`${SERVER_IP}:${ZONE_PORTS[0]}`, "utf8") };
            }
            return { ...f };
          });
          return { ...n, fields };
        });
        body = sdp.encode(out);
      } catch (_) {
        body = null;
      }
    }
    sock.write(renderFrame(entry, seq, body));
    return;
  }

  // Fallback (bila template tidak ada): builder lama.
  let built = null;
  if (opcode === 0x70000101) {
    console.log(`[${label}] Cmd_Login_Auth_CS -> Cmd_Login_Auth_SC`);
    let csBody = null;
    if (style === "probe") {
      const inner = probeUnpack(raw);
      const parsed = probeParseInner(inner);
      csBody = parsed ? parsed.body : null;
    } else {
      csBody = sdp.parseFrame(raw).body;
    }
    const cs = Cmd_Login_Auth_CS.fromSdpBody(csBody);
    const account = findAuthAccount(cs) || createAuthAccount(cs);
    CURRENT_ACCOUNT = account;
    built = buildLoginAuthSC(seq, account);
  } else if (opcode === 0x70000301) {
    console.log(`[${label}] Cmd_Login_GetZone_CS -> Cmd_Login_GetZone_SC`);
    let csBody = null;
    if (style === "probe") {
      const inner = probeUnpack(raw);
      const parsed = probeParseInner(inner);
      csBody = parsed ? parsed.body : null;
    } else {
      csBody = sdp.parseFrame(raw).body;
    }
    const cs = Cmd_Login_GetZone_CS.fromSdpBody(csBody);
    const account = findAuthAccountById(cs.iAccountId);
    if (!account) {
      console.log(
        `[${label}] akun iAccountId=${cs.iAccountId} tidak ditemukan -> zone default`,
      );
    }
    built = buildLoginGetZoneSC(seq, account || undefined);
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

  // -------------------------------------------------------------------------
  // Handler emulasi: opcode yang tidak bisa dijawab hanya dengan replay cache.
  // Semua balasan memakai header/ID pesan dari request yang sesuai.
  // -------------------------------------------------------------------------
  if (EMULATE && opcode === 0x7000fa55) {
    // Cmd_Shop_BuyItem_CS -> Cmd_Shop_BuyItem_SC (rspcode 0 = sukses).
    const csBody = extractCsBody(raw);
    let moneyType = 0;
    let itemId = 0;
    let num = 1;
    try {
      const nodes = csBody ? sdp.decode(csBody) : [];
      const root = nodes.find((n) => n.type === sdp.T.STRUCT);
      const fields = root ? root.fields : nodes;
      const numOf = (tag) => {
        const f = fields.find(
          (n) => n.tag === tag && (n.type === sdp.T.INT || n.type === sdp.T.NEG),
        );
        return f ? Number(f.v) : undefined;
      };
      moneyType = numOf(0) ?? 0;
      itemId = numOf(1) ?? 0;
      num = numOf(2) ?? 1;
    } catch (_) {}
    console.log(
      `[${label}] Cmd_Shop_BuyItem_CS -> Cmd_Shop_BuyItem_SC (money=${moneyType} item=${itemId} num=${num} OK)`,
    );
    sendZoneReply(sock, 0x7000fb55, seq, raw, EMPTY_SC_BODY);
    return;
  }

  if (EMULATE && opcode === 0x7000d297) {
    // Cmd_Item_BuySkin_CS -> Cmd_Item_BuySkin_SC (echo field request).
    const csBody = extractCsBody(raw);
    const fields = [];
    try {
      const nodes = csBody ? sdp.decode(csBody) : [];
      const root = nodes.find((n) => n.type === sdp.T.STRUCT);
      for (const f of (root ? root.fields : nodes) || []) {
        if (f.type === sdp.T.INT || f.type === sdp.T.NEG) {
          fields.push(sdp.node.int(f.tag, f.v));
        } else if (f.type === sdp.T.STRING) {
          fields.push(sdp.node.str(f.tag, f.raw));
        }
      }
    } catch (_) {}
    const scBody = fields.length ? sdp.buildBody(fields) : EMPTY_SC_BODY;
    console.log(
      `[${label}] Cmd_Item_BuySkin_CS -> Cmd_Item_BuySkin_SC (echo ${fields.length} field)`,
    );
    sendZoneReply(sock, 0x7000d397, seq, raw, scBody);
    return;
  }

  if (EMULATE && opcode === 0x7000c750) {
    // Cmd_Item_Set_CurSkin_CS -> Cmd_Item_Set_CurSkin_SC.
    const csBody = extractCsBody(raw);
    let heroId = 0;
    let skinId = 0;
    try {
      const nodes = csBody ? sdp.decode(csBody) : [];
      const root = nodes.find((n) => n.type === sdp.T.STRUCT);
      const fields = root ? root.fields : nodes;
      const hf = fields.find(
        (f) => f.tag === 0 && (f.type === sdp.T.INT || f.type === sdp.T.NEG),
      );
      const sf = fields.find(
        (f) => f.tag === 1 && (f.type === sdp.T.INT || f.type === sdp.T.NEG),
      );
      if (hf) heroId = Number(hf.v);
      if (sf) skinId = Number(sf.v);
    } catch (_) {}
    if (heroId === 18 && skinId) CURRENT_SKIN_LAYLA = skinId;
    const scBody = sdp.buildBody([
      sdp.node.int(0, heroId),
      sdp.node.int(1, skinId),
    ]);
    console.log(
      `[${label}] Cmd_Item_Set_CurSkin_CS -> Cmd_Item_Set_CurSkin_SC (hero=${heroId} skin=${skinId})`,
    );
    sendZoneReply(sock, 0x7000c850, seq, raw, scBody);
    return;
  }

  if (EMULATE && (opcode === 0x7000c057 || opcode === 0x7000c257)) {
    // Start Game mengirim Cmd_Room_Enter_CS; klien hanya punya consumer untuk
    // Cmd_Room_Enter_SC. Mode create_then_enter meniru urutan server resmi.
    const cs = parseRoomEnterCS(extractCsBody(raw));
    const profile = currentRoleProfile();
    const pvpType =
      process.env.ROOM_PVP_TYPE !== undefined
        ? Number(process.env.ROOM_PVP_TYPE)
        : cs.pvpType;
    const roomMode = process.env.ROOM_REPLY_MODE || "create_then_enter";
    if (roomMode === "empty_create" || roomMode === "create_then_enter") {
      console.log(
        `[${label}] ${hex32(opcode)} -> Cmd_Room_Create_SC kosong (${roomMode})`,
      );
      sendZoneReply(sock, 0x7000c157, seq, raw, EMPTY_SC_BODY);
      if (roomMode === "create_then_enter") {
        const enterBody = buildRoomEnterSCBody({
          roomId: cs.roomId ?? 2,
          matchVersion: 100,
          pvpType,
          mapId: cs.mapId,
          pvpMode: cs.pvpMode,
          profile,
        });
        setTimeout(() => {
          if (!sock.destroyed) {
            console.log(`[${label}] push 0x7000c357 setelah Create_SC`);
            sendZoneReply(sock, 0x7000c357, seq, raw, enterBody);
          }
        }, 80);
      }
      return;
    }
    const body = buildRoomEnterSCBody({
      roomId: cs.roomId ?? 2,
      matchVersion: 100,
      pvpType,
      mapId: cs.mapId,
      pvpMode: cs.pvpMode,
      profile,
    });
    console.log(
      `[${label}] ${hex32(opcode)} -> Cmd_Room_Enter_SC (pvp=${pvpType ?? "default"} uid=${ROLE_UID})`,
    );
    sendZoneReply(sock, 0x7000c357, seq, raw, body);
    return;
  }

  if (EMULATE && opcode === 0x7000c457) {
    console.log(`[${label}] Cmd_Room_Leave_CS -> Cmd_Room_Leave_SC`);
    sendZoneReply(sock, 0x7000c557, seq, raw, EMPTY_SC_BODY);
    return;
  }

  if (EMULATE && opcode === 0x7000c857) {
    if ((process.env.ROOM_GETINFO_MODE || "empty") === "builder") {
      const body = buildRoomGetInfoSCBody({ profile: currentRoleProfile() });
      console.log(`[${label}] Cmd_Room_GetInfo_CS -> builder RoomInfo`);
      sendZoneReply(sock, 0x7000c957, seq, raw, body);
    } else {
      console.log(`[${label}] Cmd_Room_GetInfo_CS -> kosong (tidak di room)`);
      sendZoneReply(sock, 0x7000c957, seq, raw, EMPTY_SC_BODY);
    }
    return;
  }

  if (EMULATE && opcode === 0x7000d694) {
    // Cmd_Battle_GetBattleData_CS: Preparation menunggu balasan ini.
    const body = buildCmdBattleGetBattleDataSCBody(currentRoleProfile());
    const entry = REPLAY_CACHE.get(hex32(0x7000d794));
    let scBody = body;
    if (entry) {
      try {
        scBody = patchCmdBattleGetBattleDataBody(entry.body, currentRoleProfile());
      } catch (_) {
        scBody = body;
      }
    }
    console.log(
      `[${label}] Cmd_Battle_GetBattleData_CS -> Cmd_Battle_GetBattleData_SC (uid=${ROLE_UID} svr=${ROLE_SVR_ID})`,
    );
    sendZoneReply(sock, 0x7000d794, seq, raw, scBody);
    return;
  }

  const respOpcode = (opcode + 0x100) >>> 0;
  let entry = REPLAY_CACHE.get(hex32(respOpcode));
  // Role_Init standalone: pakai template disematkan, bukan capture file.
  if (respOpcode === ROLE_INIT_SC && ROLE_INIT_SC_TEMPLATE) {
    const inner = probeUnpack(ROLE_INIT_SC_TEMPLATE);
    const parsed = probeParseInner(inner);
    entry = {
      kind: "probe",
      opcode: parsed.opcode,
      raw: ROLE_INIT_SC_TEMPLATE,
      inner,
      headerPos: parsed.headerPos,
      body: parsed.body,
    };
  }
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
  if (NAME_OVERRIDE && respOpcode === ROLE_INIT_SC) {
    // Cari akun dari request Role_Init (tag 8 = sAccountName) agar patch
    // tidak bergantung pada global CURRENT_ACCOUNT (bisa null pada koneksi awal).
    let account = CURRENT_ACCOUNT;
    try {
      let reqBody = null;
      if (raw && raw.length > 4 && raw[0] === 0x10 && raw[1] === 0x00) {
        const innerReq = probeUnpack(raw);
        const parsedReq = probeParseInner(innerReq);
        reqBody = parsedReq ? parsedReq.body : null;
      } else if (raw && raw.length >= 9) {
        reqBody = sdp.parseFrame(raw).body;
      }
      if (reqBody) {
        const nodes = sdp.decode(reqBody);
        const root = nodes[0];
        const nameField = root && root.fields ? root.fields.find((f) => f.tag === 8) : null;
        const accountName = nameField && nameField.raw ? nameField.raw.toString("utf8") : "";
        if (accountName) {
          const found = findAuthAccount({ sAccountName: accountName, sAuthKey: "" });
          if (found) account = found;
        }
      }
    } catch (_) {
      // biarkan fallback ke CURRENT_ACCOUNT
    }
    let accountId = account ? Number(account.iAccountId || 0) : 0;
    if (!accountId) accountId = 1;
    const name = ROLE_NAME;
    body = patchRoleInitBinary(body || entry.body, DIAMOND, LEVEL, ROLE_UID, name);
    console.log(
      `[${label}] override iUid=${ROLE_UID} sName=${name} iDiamond=${DIAMOND} iLevel=${LEVEL} pada Cmd_Role_Init_SC`,
    );
  }
  if (NAME_OVERRIDE && respOpcode === ROLE_INFO_SC) {
    // Klien menyegarkan info role lewat opcode ini; tanpa patch, level kembali
    // ke nilai capture lama.
    body = patchField(body || entry.body, LEVEL_TAG, LEVEL);
    // Patch iUid (tag 0) dan sName (tag 2) agar nama di lobby berubah.
    try {
      const acc = CURRENT_ACCOUNT;
      const aid = ROLE_UID;
      const nm = ROLE_NAME;
      const nodes = sdp.decode(body || entry.body);
      const out = nodes.map((n) => {
        if (n.type !== sdp.T.STRUCT) return n;
        const fields = n.fields.map((f) => {
          if (f.tag === 0 && (f.type === sdp.T.INT || f.type === sdp.T.NEG)) {
            return { ...f, type: sdp.T.INT, v: BigInt(aid) };
          }
          if (f.tag === 2 && f.type === sdp.T.STRING) {
            return { ...f, raw: Buffer.from(nm, "utf8") };
          }
          return { ...f };
        });
        return { ...n, fields };
      });
      body = sdp.encode(out);
    } catch (_) {}
    console.log(`[${label}] override iUid/sName/iLevel pada Cmd_Role_GetInfo_SC`);
  }
  if (NAME_OVERRIDE && respOpcode === ACCOUNT_GET_SC) {
    try {
      const acc = CURRENT_ACCOUNT;
      const aid = ROLE_UID;
      const nm = ROLE_NAME;
      const nodes = sdp.decode(body || entry.body);
      const out = nodes.map((n) => {
        if (n.type !== sdp.T.STRUCT) return n;
        const fields = n.fields.map((f) => {
          if (f.tag === 0 && (f.type === sdp.T.INT || f.type === sdp.T.NEG)) {
            return { ...f, type: sdp.T.INT, v: BigInt(aid) };
          }
          if (f.tag === 2 && f.type === sdp.T.LIST) {
            const items = f.items.map((it) => {
              if (it.type !== sdp.T.STRUCT) return it;
              const fs2 = it.fields.map((ff) => {
                if (ff.tag === 1 && (ff.type === sdp.T.INT || ff.type === sdp.T.NEG)) {
                  return { ...ff, type: sdp.T.INT, v: BigInt(aid) };
                }
                if (ff.tag === 2 && ff.type === sdp.T.STRING) {
                  return { ...ff, raw: Buffer.from(nm, "utf8") };
                }
                return { ...ff };
              });
              return { ...it, fields: fs2 };
            });
            return { ...f, items };
          }
          return { ...f };
        });
        return { ...n, fields };
      });
      body = sdp.encode(out);
    } catch (_) {}
    console.log(`[${label}] override iUid/sName pada Cmd_Account_GetAccount_SC`);
  }
  if (EMULATE && respOpcode === 0x7000a251) {
    try {
      body = patchCmdHeroGetListBody(body || entry.body);
      console.log(
        `[${label}] patch Cmd_Hero_GetList_SC: hero 18 skin=${CURRENT_SKIN_LAYLA}, hero 25 + skin 1188/1189`,
      );
    } catch (e) {
      console.log(`[${label}] PATCH GAGAL Cmd_Hero_GetList_SC: ${e.message}`);
      body = entry.body;
    }
  }
  if (EMULATE && respOpcode === 0x7000d794) {
    try {
      body = patchCmdBattleGetBattleDataBody(
        body || entry.body,
        currentRoleProfile(),
      );
      console.log(
        `[${label}] patch Cmd_Battle_GetBattleData_SC uid=${ROLE_UID} svr=${ROLE_SVR_ID}`,
      );
    } catch (e) {
      console.log(`[${label}] PATCH GAGAL Cmd_Battle_GetBattleData_SC: ${e.message}`);
      body = entry.body;
    }
  }
  if (NAME_OVERRIDE) body = patchLegacyRoleName(body || entry.body, ROLE_NAME);
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
        if (!sock.destroyed) {
          const pushBody = NAME_OVERRIDE
            ? patchLegacyRoleName(pushEntry.body, ROLE_NAME)
            : null;
          sock.write(renderFrame(pushEntry, seq, pushBody));
        }
      }, 80);
    }
  }
}

/** Parser stream generik: mendukung frame biasa maupun amplop probe. */
function makeZoneHandler(sock, label) {
  let buf = Buffer.alloc(0);

  // Hybrid: koneksi ke server resmi untuk fallback paket unknown.
  let upSock = null;
  let upBuf = Buffer.alloc(0);
  if (MODE === "hybrid") {
    upSock = net.connect(ZONE_UPSTREAM.port, ZONE_UPSTREAM.host, () => {
      console.log(`[${label}] hybrid upstream ${ZONE_UPSTREAM.host}:${ZONE_UPSTREAM.port}`);
    });
    upSock.on("data", (chunk) => {
      upBuf = upBuf.length ? Buffer.concat([upBuf, chunk]) : chunk;
      for (;;) {
        if (upBuf.length < 4) break;
        const total = probeTotal(upBuf);
        if (total !== null) {
          if (total < 4 || upBuf.length < total) break;
          const pkt = upBuf.subarray(0, total);
          upBuf = upBuf.subarray(total);
          const inner = probeUnpack(pkt);
          const p = inner ? probeParseInner(inner) : null;
          const opcode = p ? p.opcode : null;
          const known = opcode && REPLAY_CACHE.has(hex32(opcode));
          if (!known && !sock.destroyed) sock.write(pkt);
          continue;
        }
        const len = upBuf.readUInt32BE(0);
        if (len < 9 || len > MAX_FRAME) { upBuf = Buffer.alloc(0); break; }
        if (upBuf.length < len) break;
        const pkt = upBuf.subarray(0, len);
        upBuf = upBuf.subarray(len);
        const opcode = pkt.readUInt32BE(4);
        const known = REPLAY_CACHE.has(hex32(opcode));
        if (!known && !sock.destroyed) sock.write(pkt);
      }
    });
    upSock.on("error", (e) => console.log(`[${label}] hybrid upstream error: ${e.message}`));
    upSock.on("close", () => { upSock = null; });
  }

  sock.on("data", (chunk) => {
    if (upSock && !upSock.destroyed) upSock.write(chunk);
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
  sock.on("close", () => { if (upSock && !upSock.destroyed) upSock.destroy(); });
}

function makeAuthHandler(sock, label) {
  let buf = Buffer.alloc(0);

  let upSock = null;
  let upBuf = Buffer.alloc(0);
  if (MODE === "hybrid") {
    upSock = net.connect(AUTH_UPSTREAM.port, AUTH_UPSTREAM.host, () => {
      console.log(`[${label}] hybrid upstream ${AUTH_UPSTREAM.host}:${AUTH_UPSTREAM.port}`);
    });
    upSock.on("data", (chunk) => {
      upBuf = upBuf.length ? Buffer.concat([upBuf, chunk]) : chunk;
      for (;;) {
        if (upBuf.length < 4) break;
        const total = probeTotal(upBuf);
        if (total !== null) {
          if (total < 4 || upBuf.length < total) break;
          const pkt = upBuf.subarray(0, total);
          upBuf = upBuf.subarray(total);
          const inner = probeUnpack(pkt);
          const p = inner ? probeParseInner(inner) : null;
          const opcode = p ? p.opcode : null;
          // Auth responses are all handled locally (template/builder), drop upstream.
          if (opcode && !sock.destroyed) {
            // drop known; forward unknown (none expected)
            if (!REPLAY_CACHE.has(hex32(opcode))) {
              sock.write(pkt);
            }
          } else if (!sock.destroyed) {
            sock.write(pkt);
          }
          continue;
        }
        const len = upBuf.readUInt32BE(0);
        if (len < 9 || len > MAX_FRAME) { upBuf = Buffer.alloc(0); break; }
        if (upBuf.length < len) break;
        const pkt = upBuf.subarray(0, len);
        upBuf = upBuf.subarray(len);
        const opcode = pkt.readUInt32BE(4);
        if (!REPLAY_CACHE.has(hex32(opcode)) && !sock.destroyed) sock.write(pkt);
      }
    });
    upSock.on("error", (e) => console.log(`[${label}] hybrid upstream error: ${e.message}`));
    upSock.on("close", () => { upSock = null; });
  }

  sock.on("data", (chunk) => {
    if (upSock && !upSock.destroyed) upSock.write(chunk);
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
  sock.on("close", () => { if (upSock && !upSock.destroyed) upSock.destroy(); });
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
  if (MODE !== "replay" && MODE !== "emulate" && MODE !== "hybrid") {
    console.error(`[SERVER] MODE tidak dikenal: ${MODE}. Pakai replay|emulate|hybrid`);
    process.exit(1);
  }

  console.log(`[SERVER] cache replay: ${REPLAY_CACHE.size} opcode`);
  if (NAME_OVERRIDE) {
    console.log(`[SERVER] override nama role: ${ROLE_NAME}`);
  }
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
  patchRoleInitBinary,
  patchAuthSimpleRoleInfo,
  patchCmdHeroGetListBody,
  patchCmdBattleGetBattleDataBody,
  buildCmdBattleGetBattleDataSCBody,
  extractCsBody,
  sendZoneReply,
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
  ROLE_UID,
  ROLE_NAME,
  ROLE_SVR_ID,
  AUTH_UID_VALUE,
};

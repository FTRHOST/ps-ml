/**
 * sdp.js - Decoder + Encoder SDP (Moonton/Tars-like) dengan round-trip exact.
 *
 * Node = { tag, type, ... }
 *   type 0  int    { v: BigInt >= 0 }            varint positif
 *   type 1  int    { v: BigInt <  0 }            varint magnitude, nilai negatif
 *   type 2  float  { v: number }                 4B LE
 *   type 3  double { v: number }                 8B LE
 *   type 4  string { raw: Buffer }               varint len + bytes
 *   type 5  list   { items: Node[] }             varint count + item (header bertag 0)
 *   type 6  map    { entries: [Node, Node][] }   varint count + (key, value)
 *   type 7  struct { fields: Node[] }            sampai StructEnd (type 8)
 *   type 8  end    {}                            StructEnd "yatim" di top-level
 *
 * Asumsi yang HARUS diverifikasi dengan capture asli (lihat test-sdp.js):
 *   - elemen list/map memakai header bertag 0
 *   - tipe 1 = integer negatif (magnitude varint)
 */

const T = { INT: 0, NEG: 1, FLOAT: 2, DOUBLE: 3, STRING: 4, LIST: 5, MAP: 6, STRUCT: 7, END: 8 };

// ---------------- varint ----------------
function readVarUint(buf, pos) {
  let val = 0n, shift = 0n, start = pos;
  for (;;) {
    if (pos >= buf.length) throw new Error(`varint terpotong @${start}`);
    const b = buf[pos++];
    val |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7n;
    if (shift > 70n) throw new Error(`varint terlalu panjang @${start}`);
  }
  return { val, next: pos };
}

function writeVarUint(v) {
  let x = BigInt(v);
  if (x < 0n) throw new Error("varint negatif");
  const out = [];
  do {
    let b = Number(x & 0x7fn);
    x >>= 7n;
    if (x !== 0n) b |= 0x80;
    out.push(b);
  } while (x !== 0n);
  return Buffer.from(out);
}

// ---------------- header ----------------
function writeHeader(tag, type) {
  // tag 0..14 masuk nibble; tag >= 15 memakai penanda 0xf lalu tag sebagai VARINT
  // (bukan satu byte — tag >= 128 butuh 2 byte, mis. 129 = 81 01).
  if (tag < 15) return Buffer.from([(type << 4) | tag]);
  return Buffer.concat([Buffer.from([(type << 4) | 15]), writeVarUint(tag)]);
}

function readHeader(buf, pos) {
  if (pos >= buf.length) throw new Error(`header di luar buffer @${pos}`);
  const b = buf[pos++];
  const type = b >> 4;
  let tag = b & 0x0f;
  if (tag === 15) {
    if (pos >= buf.length) throw new Error(`tag extended terpotong @${pos}`);
    const r = readVarUint(buf, pos);
    tag = Number(r.val);
    pos = r.next;
  }
  return { type, tag, next: pos };
}

// ---------------- decode ----------------
function decodeNode(buf, pos) {
  const h = readHeader(buf, pos);
  const { type, tag } = h;
  pos = h.next;

  switch (type) {
    case T.INT: {
      const r = readVarUint(buf, pos);
      return [{ tag, type, v: r.val }, r.next];
    }
    case T.NEG: {
      const r = readVarUint(buf, pos);
      return [{ tag, type, v: -r.val }, r.next];
    }
    case T.FLOAT:
      if (pos + 4 > buf.length) throw new Error(`float terpotong @${pos}`);
      return [{ tag, type, v: buf.readFloatLE(pos) }, pos + 4];
    case T.DOUBLE:
      if (pos + 8 > buf.length) throw new Error(`double terpotong @${pos}`);
      return [{ tag, type, v: buf.readDoubleLE(pos) }, pos + 8];
    case T.STRING: {
      const r = readVarUint(buf, pos);
      const len = Number(r.val);
      if (r.next + len > buf.length) throw new Error(`string terpotong @${pos}`);
      return [{ tag, type, raw: Buffer.from(buf.subarray(r.next, r.next + len)) }, r.next + len];
    }
    case T.LIST: {
      const r = readVarUint(buf, pos);
      pos = r.next;
      const items = [];
      for (let i = 0n; i < r.val; i++) {
        const [n, nx] = decodeNode(buf, pos);
        items.push(n);
        pos = nx;
      }
      return [{ tag, type, items }, pos];
    }
    case T.MAP: {
      const r = readVarUint(buf, pos);
      pos = r.next;
      const entries = [];
      for (let i = 0n; i < r.val; i++) {
        const [k, p1] = decodeNode(buf, pos);
        const [v, p2] = decodeNode(buf, p1);
        entries.push([k, v]);
        pos = p2;
      }
      return [{ tag, type, entries }, pos];
    }
    case T.STRUCT: {
      const fields = [];
      for (;;) {
        if (pos >= buf.length) throw new Error("struct tidak ditutup (StructEnd hilang)");
        if (buf[pos] >> 4 === T.END) {
          const e = readHeader(buf, pos);
          pos = e.next;
          break;
        }
        const [n, nx] = decodeNode(buf, pos);
        fields.push(n);
        pos = nx;
      }
      return [{ tag, type, fields }, pos];
    }
    case T.END:
      return [{ tag, type }, pos];
    default:
      throw new Error(`tipe SDP tidak dikenal ${type} (tag ${tag}) @${pos - 1}`);
  }
}

/** Decode body SDP menjadi daftar node top-level (StructEnd yatim ikut tersimpan). */
function decode(buf, start = 0) {
  const nodes = [];
  let pos = start;
  while (pos < buf.length) {
    const [n, nx] = decodeNode(buf, pos);
    nodes.push(n);
    pos = nx;
  }
  return nodes;
}

// ---------------- encode ----------------
function encodeNode(n) {
  const h = writeHeader(n.tag, n.type);
  switch (n.type) {
    case T.INT:
    case T.NEG:
      return Buffer.concat([h, writeVarUint(n.v < 0n ? -n.v : n.v)]);
    case T.FLOAT: {
      const b = Buffer.alloc(4);
      b.writeFloatLE(n.v);
      return Buffer.concat([h, b]);
    }
    case T.DOUBLE: {
      const b = Buffer.alloc(8);
      b.writeDoubleLE(n.v);
      return Buffer.concat([h, b]);
    }
    case T.STRING:
      return Buffer.concat([h, writeVarUint(n.raw.length), n.raw]);
    case T.LIST:
      return Buffer.concat([h, writeVarUint(n.items.length), ...n.items.map(encodeNode)]);
    case T.MAP:
      return Buffer.concat([
        h,
        writeVarUint(n.entries.length),
        ...n.entries.flatMap(([k, v]) => [encodeNode(k), encodeNode(v)]),
      ]);
    case T.STRUCT:
      return Buffer.concat([h, ...n.fields.map(encodeNode), writeHeader(0, T.END)]);
    case T.END:
      return h;
    default:
      throw new Error(`tipe tidak dikenal ${n.type}`);
  }
}

function encode(nodes) {
  return Buffer.concat(nodes.map(encodeNode));
}

// ---------------- builder ringkas (untuk server) ----------------
const node = {
  int: (tag, v) => ({ tag, type: BigInt(v) < 0n ? T.NEG : T.INT, v: BigInt(v) }),
  str: (tag, s) => ({ tag, type: T.STRING, raw: Buffer.isBuffer(s) ? s : Buffer.from(s ?? "", "utf8") }),
  list: (tag, items) => ({ tag, type: T.LIST, items }),
  map: (tag, entries) => ({ tag, type: T.MAP, entries }),
  struct: (tag, fields) => ({ tag, type: T.STRUCT, fields }),
  float: (tag, v) => ({ tag, type: T.FLOAT, v }),
  double: (tag, v) => ({ tag, type: T.DOUBLE, v }),
};

/** Body SDP normal = root struct (tag 0) + 1 StructEnd penutup (tidak dihitung di length). */
function buildBody(fields) {
  return encode([node.struct(0, fields), { tag: 0, type: T.END }]);
}

// ---------------- frame ----------------
/**
 * Frame: [len u32BE][opcode u32BE][hdr...][body]
 *  - "game"  (lama): hdr = seq, 02 00, 05 00, 45|46, varint(bodyLen-1)
 *  - "login" (lama): hdr = seq, 45|46, varint(bodyLen-1)
 *  - "compact"     : hdr = seq, lalu body langsung (mis. reject cold-start: 15 2d 80)
 *  - format live 2.2.29: hdr = 1..3 varint (seq + kolom tambahan), 45|46, varint(bodyLen-1)
 *
 * Format baru dideteksi lebih dulu dengan validasi ketat: posisi body + panjang body
 * harus persis sama dengan len. `hdr` menyimpan byte header apa adanya supaya
 * buildFrame bisa mereproduksi frame secara byte-identik.
 */
function parseFrame(buf) {
  if (buf.length < 9) throw new Error("frame terlalu pendek");
  const len = buf.readUInt32BE(0);
  const opcode = buf.readUInt32BE(4);

  for (let k = 1; k <= 3; k++) {
    let pos = 8;
    try {
      for (let i = 0; i < k; i++) pos = readVarUint(buf, pos).next;
    } catch (_) {
      break;
    }
    if (pos < len && (buf[pos] === 0x45 || buf[pos] === 0x46)) {
      const r = readVarUint(buf, pos + 1);
      if (r.next + Number(r.val) + 1 === len) {
        return {
          len, opcode, seq: buf[8],
          envelope: buf[pos] === 0x46 ? "game-sc" : "game-cs",
          declaredLen: Number(r.val) + 1,
          bodyStart: r.next,
          hdr: buf.subarray(8, r.next),
          body: buf.subarray(r.next, len),
        };
      }
    }
  }

  let envelope = "compact";
  let bodyStart = 9;
  let declaredLen = null;

  if (buf[9] === 0x02 && buf[10] === 0x00 && buf[11] === 0x05 && buf[12] === 0x00 && (buf[13] === 0x46 || buf[13] === 0x45)) {
    envelope = buf[13] === 0x46 ? "game-sc" : "game-cs";
    const r = readVarUint(buf, 14);
    declaredLen = Number(r.val) + 1;
    bodyStart = r.next;
  } else if (buf[9] === 0x45 || buf[9] === 0x46) {
    // Login lama: seq, penanda arah, varint(bodyLen-1). Validasi panjang dulu.
    const r = readVarUint(buf, 10);
    if (r.next + Number(r.val) + 1 === len) {
      envelope = buf[9] === 0x46 ? "login-sc" : "login-cs";
      declaredLen = Number(r.val) + 1;
      bodyStart = r.next;
    }
  }
  return {
    len, opcode, seq: buf[8], envelope, declaredLen, bodyStart,
    hdr: buf.subarray(8, bodyStart),
    body: buf.subarray(bodyStart, len),
  };
}

function buildFrame(opcode, seq, bodyBuf, envelope = "game-sc", hdr = null) {
  let payload;
  if (hdr) {
    // Rekonstruksi byte-identik: pakai header asli hasil parseFrame.
    payload = Buffer.concat([hdr, bodyBuf]);
  } else if (envelope === "compact") {
    payload = Buffer.concat([Buffer.from([seq]), bodyBuf]);
  } else if (envelope === "login-cs" || envelope === "login-sc") {
    payload = Buffer.concat([
      Buffer.from([seq, envelope === "login-cs" ? 0x45 : 0x46]),
      writeVarUint(bodyBuf.length - 1),
      bodyBuf,
    ]);
  } else {
    payload = Buffer.concat([
      Buffer.from([seq, 0x02, 0x00, 0x05, 0x00, envelope === "game-cs" ? 0x45 : 0x46]),
      writeVarUint(bodyBuf.length - 1),
      bodyBuf,
    ]);
  }
  const head = Buffer.alloc(8);
  head.writeUInt32BE(payload.length + 8, 0);
  head.writeUInt32BE(opcode >>> 0, 4);
  return Buffer.concat([head, payload]);
}

// ---------------- tampilan ----------------
const TYPE_NAMES = ["int", "neg", "float", "double", "string", "list", "map", "struct", "end"];

function strText(raw) {
  const s = raw.toString("utf8");
  return /[\x00-\x08\x0e-\x1f]/.test(s) || Buffer.from(s, "utf8").compare(raw) !== 0
    ? `<hex ${raw.toString("hex")}>`
    : JSON.stringify(s);
}

function toText(nodes, depth = 0, names = null) {
  const ind = "  ".repeat(depth);
  const lines = [];
  for (const n of nodes) {
    const label = names && names[n.tag] ? `${n.tag}:${names[n.tag]}` : `${n.tag}`;
    switch (n.type) {
      case T.INT:
      case T.NEG:
        lines.push(`${ind}[${label}] ${TYPE_NAMES[n.type]} = ${n.v}`);
        break;
      case T.FLOAT:
      case T.DOUBLE:
        lines.push(`${ind}[${label}] ${TYPE_NAMES[n.type]} = ${n.v}`);
        break;
      case T.STRING:
        lines.push(`${ind}[${label}] string(${n.raw.length}) = ${strText(n.raw)}`);
        break;
      case T.LIST:
        lines.push(`${ind}[${label}] list(${n.items.length}) [`);
        lines.push(toText(n.items, depth + 1));
        lines.push(`${ind}]`);
        break;
      case T.MAP:
        lines.push(`${ind}[${label}] map(${n.entries.length}) {`);
        for (const [k, v] of n.entries) lines.push(toText([k, v], depth + 1));
        lines.push(`${ind}}`);
        break;
      case T.STRUCT:
        lines.push(`${ind}[${label}] struct {`);
        lines.push(toText(n.fields, depth + 1));
        lines.push(`${ind}}`);
        break;
      case T.END:
        lines.push(`${ind}<StructEnd tambahan>`);
        break;
    }
  }
  return lines.filter((l) => l !== "").join("\n");
}

module.exports = {
  T, node, decode, encode, decodeNode, encodeNode,
  parseFrame, buildFrame, buildBody,
  readVarUint, writeVarUint, toText,
};

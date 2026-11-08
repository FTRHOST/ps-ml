#!/usr/bin/env node
/**
 * Fase 2 — gabungkan tiga sumber menjadi schema/schema.json:
 *   - dump.cs                      : class + nama field + tipe (struktur)
 *   - mlbb_captured_tags/opcodes.jsonl : opcode -> class (dari PackUtil.Unpack)
 *   - mlbb_captured_tags/tags.jsonl    : tag + nama field + require (dari visit)
 *
 * Nomor tag TIDAK ada di dump.cs, jadi tag diambil dari tags.jsonl dengan
 * mencocokkan nama field. Urutan field mengikuti dump.cs (deklarasi asli).
 *
 * Pemakaian:
 *   node tools/build-schema.js
 *   node tools/build-schema.js --check     # hanya parse dump.cs
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DUMP_FILE = process.env.DUMP_CS || path.join(ROOT, "dump.cs");
const TAG_FILE = path.join(ROOT, "mlbb_captured_tags", "tags.jsonl");
const OPCODE_FILE = path.join(ROOT, "mlbb_captured_tags", "opcodes.jsonl");
const OUT_FILE = path.join(ROOT, "schema", "schema.json");

const PRIMITIVES = new Map([
  ["System.String", "string"],
  ["System.Boolean", "bool"],
  ["System.Byte", "int"],
  ["System.SByte", "int"],
  ["System.Int16", "int"],
  ["System.UInt16", "int"],
  ["System.Int32", "int"],
  ["System.UInt32", "int"],
  ["System.Int64", "int64"],
  ["System.UInt64", "int64"],
  ["System.Single", "float"],
  ["System.Double", "double"],
  ["System.Byte[]", "bytes"],
]);

/** Parse dump.cs menjadi Map<namaClass, {fields:[{offset,name,type}]}>. */
function parseDump(text) {
  const classes = new Map();
  let current = null;
  for (const line of text.split("\n")) {
    const head = /^class (\S+) \{/.exec(line);
    if (head) {
      current = { name: head[1], fields: [] };
      classes.set(current.name, current);
      continue;
    }
    if (line === "}" && current) {
      current = null;
      continue;
    }
    if (!current) continue;
    const f = /^\s*\[Field\] (0x[0-9a-fA-F]+) : (.+?) (\S+)$/.exec(line);
    if (f) current.fields.push({ offset: f[1], type: f[2], name: f[3] });
  }
  return classes;
}

/** Ubah tipe C# menjadi deskripsi tipe SDP yang netral. */
function normalizeType(csharp) {
  if (PRIMITIVES.has(csharp)) return { kind: PRIMITIVES.get(csharp) };
  let m = /^System\.Collections\.Generic\.List<(.+)>$/.exec(csharp);
  if (m) return { kind: "list", of: normalizeType(m[1]) };
  m = /^System\.Collections\.Generic\.Dictionary<(.+),(.+)>$/.exec(csharp);
  if (m) return { kind: "map", key: normalizeType(m[1]), value: normalizeType(m[2]) };
  // Class lain (biasanya struct SDP): simpan nama tanpa namespace.
  const short = csharp.replace(/^[A-Za-z0-9_.]+\./, "");
  return { kind: "struct", class: short };
}

/** Baca jsonl, abaikan baris rusak. */
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  const out = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch (_) {}
  }
  return out;
}

/**
 * Kelompokkan event tag menjadi "sesi pesan": sederet event dengan opcode+thread
 * sama. Satu kunjungan Unpack menghasilkan satu blok, termasuk visit struct anak.
 */
// Opcode game selalu 0x70xxxxxx; nilai lain (mis. pointer dari argumen salah)
// dibuang supaya tidak mengotori skema.
const OPCODE_RE = /^0x70[0-9a-f]{6}$/;

function groupTagSessions(tags) {
  const sessions = [];
  let prevKey = null;
  for (const t of tags) {
    if (!t.opcode || !OPCODE_RE.test(t.opcode)) continue;
    const key = t.opcode + "|" + t.thread;
    if (key !== prevKey || !sessions.length) {
      sessions.push({ opcode: t.opcode, thread: t.thread, visits: [] });
      prevKey = key;
    }
    sessions[sessions.length - 1].visits.push(t);
  }
  return sessions;
}

/** opcode -> class (ambil yang paling sering muncul; seri -> terbaru). */
function buildOpcodeMap(entries) {
  const stat = new Map();
  for (const e of entries) {
    if (!e.opcode || !OPCODE_RE.test(e.opcode) || !e.class_name) continue;
    if (!stat.has(e.opcode)) stat.set(e.opcode, { count: {}, last: {} });
    const s = stat.get(e.opcode);
    s.count[e.class_name] = (s.count[e.class_name] || 0) + 1;
    s.last[e.class_name] = e.timestamp || 0;
  }
  const map = new Map();
  for (const [opcode, s] of stat) {
    let best = null;
    for (const name of Object.keys(s.count)) {
      const score = [s.count[name], s.last[name]];
      if (
        !best ||
        score[0] > best.score[0] ||
        (score[0] === best.score[0] && score[1] > best.score[1])
      ) {
        best = { name, score };
      }
    }
    if (best) map.set(opcode, best.name);
  }
  return map;
}

/**
 * Cari tag untuk tiap field top-level lewat nama di sesi visit.
 * Tag diambil dari data nyata (bukan indeks), karena urutan deklarasi dump.cs
 * sesekali bergeser satu tag (mis. Cmd_Role_Init_SC.sClientGuide = tag 49).
 * Bila field tak pernah muncul, pakai indeks deklarasi sebagai tebakan dan
 * tandai inferred=true.
 */
function tagFields(fields, sessions) {
  const byName = new Map(); // field_name -> Map(tag -> jumlah kemunculan)
  for (const s of sessions) {
    for (const v of s.visits) {
      if (v.field_name === "unknown" || v.field_name === "empty") continue;
      if (!byName.has(v.field_name)) byName.set(v.field_name, new Map());
      const tags = byName.get(v.field_name);
      tags.set(v.tag, (tags.get(v.tag) || 0) + 1);
    }
  }
  return fields.map((f, i) => {
    const tags = byName.get(f.name);
    let tag = null;
    let inferred = false;
    if (tags && tags.size) {
      let best = null;
      for (const [t, c] of tags) if (!best || c > best.c) best = { t, c };
      tag = best.t;
    } else {
      tag = i;
      inferred = true;
    }
    return {
      tag,
      name: f.name,
      type: normalizeType(f.type),
      offset: f.offset,
      inferred,
    };
  });
}

function main() {
  const checkOnly = process.argv.includes("--check");
  if (!fs.existsSync(DUMP_FILE)) {
    console.error(`[!] dump.cs tidak ditemukan: ${DUMP_FILE}`);
    process.exit(1);
  }
  const classes = parseDump(fs.readFileSync(DUMP_FILE, "utf8"));
  const cmdClasses = [...classes.keys()].filter((n) => /^Cmd_.*_(CS|SC)$/.test(n));
  console.log(`[i] ${classes.size} class terbaca, ${cmdClasses.length} class Cmd_*_(CS|SC)`);

  if (checkOnly) {
    const sample = cmdClasses.slice(0, 3);
    for (const name of sample) {
      const c = classes.get(name);
      console.log(`\n${name} (${c.fields.length} field)`);
      for (const f of c.fields.slice(0, 4)) {
        console.log(`  ${f.offset} ${f.name}: ${f.type} -> ${JSON.stringify(normalizeType(f.type))}`);
      }
    }
    return;
  }

  const opcodeMap = buildOpcodeMap(readJsonl(OPCODE_FILE));
  const sessions = groupTagSessions(readJsonl(TAG_FILE));
  console.log(`[i] ${opcodeMap.size} opcode terpetakan, ${sessions.length} sesi tag`);

  const byOpcode = new Map();
  for (const s of sessions) {
    if (!byOpcode.has(s.opcode)) byOpcode.set(s.opcode, []);
    byOpcode.get(s.opcode).push(s);
  }

  const schema = { generated_at: new Date().toISOString(), source: {
    dump: path.basename(DUMP_FILE), tags: "tags.jsonl", opcodes: "opcodes.jsonl" },
    opcodes: {} };
  let named = 0;
  for (const [opcode, className] of opcodeMap) {
    const cls = classes.get(className);
    if (!cls) continue;
    const sessionsForOp = byOpcode.get(opcode) || [];
    schema.opcodes[opcode] = {
      class: className,
      fields: tagFields(cls.fields, sessionsForOp),
    };
    named++;
  }

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(schema, null, 2) + "\n");
  console.log(`[✓] ${named} opcode -> class ditulis ke ${path.relative(ROOT, OUT_FILE)}`);
  if (opcodeMap.size) {
    console.log(`[i] cakupan: ${named}/${opcodeMap.size} opcode punya class di dump.cs`);
  }
}

main();

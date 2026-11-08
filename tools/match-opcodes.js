#!/usr/bin/env node
/**
 * match-opcodes.js
 *
 * Memetakan opcode wire (mis. 0x7000a251) ke nama class SDP
 * (mis. Cmd_Hero_GetList_SC) TANPA mengandalkan urutan atau timestamp.
 *
 * Caranya:
 *   1. Baca mlbb_captured_tags/sdp_bodies.jsonl  -> pasangan (class_name, body_hex)
 *      yang dipancarkan langsung oleh hook PackUtil.Unpack.
 *   2. Baca semua paket RECV_*.json / SEND_*.json, ekstrak body SDP-nya dengan
 *      pemindai amplop 0x45/0x46 + varint (sama seperti alat analisis lain).
 *   3. Cocokkan body_hex ke body paket secara exact. Opcode wire = 4 byte awal
 *      raw paket. Suara dikumpulkan per (opcode, class).
 *   4. Tulis mlbb_captured_tags/opcodes.jsonl.
 *
 * Output satu baris per opcode:
 *   { "opcode":"0x7000a251", "class_name":"Cmd_Hero_GetList_SC",
 *     "direction":"RECV", "votes":10, "total":10, "confidence":1 }
 *
 * Pemakaian:
 *   node tools/match-opcodes.js [--dir mlbb_captured_tags] [--out ...]
 */

"use strict";

const fs = require("fs");
const path = require("path");

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const DIR = arg("--dir", "mlbb_captured_tags");
const OUT = arg("--out", path.join(DIR, "opcodes.jsonl"));

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, "utf8").trim();
  if (!text) return [];
  const rows = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch (_) {
      /* abaikan baris rusak */
    }
  }
  return rows;
}

/** Baca varint unsigned; kembalikan {val, next} atau null. */
function readVarUint(buf, pos) {
  let val = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= buf.length) return null;
    const b = buf[pos++];
    val |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return { val: Number(val), next: pos };
    shift += 7n;
    if (shift > 63n) return null;
  }
}

/**
 * Ekstrak body SDP dari raw paket.
 * Format: [opcode u32][seq u8][varint...][0x45|0x46][varint(bodyLen-1)][body]
 * Pemindai mencoba posisi penanda 4..23 dan memvalidasi panjang tepat.
 */
function extractBody(raw) {
  if (!raw || raw.length < 9) return null;
  for (let p = 4; p < Math.min(raw.length - 2, 24); p++) {
    if (raw[p] !== 0x45 && raw[p] !== 0x46) continue;
    const r = readVarUint(raw, p + 1);
    if (!r) continue;
    const bodyStart = r.next;
    const bodyLen = r.val + 1;
    const end = bodyStart + bodyLen;
    if (end === raw.length || end === raw.length - 1) {
      return raw.subarray(bodyStart, end);
    }
  }
  return null;
}

function main() {
  const bodies = readJsonl(path.join(DIR, "sdp_bodies.jsonl"));
  if (!bodies.length) {
    console.error("[!] sdp_bodies.jsonl kosong. Jalankan collector dulu.");
    process.exit(1);
  }

  // Peta bodyHex -> daftar {opcode, direction}.
  const index = new Map();
  const files = fs
    .readdirSync(DIR)
    .filter((f) => /^(RECV|SEND)_.*\.json$/.test(f));

  for (const f of files) {
    let rec;
    try {
      rec = JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8"));
    } catch (_) {
      continue;
    }
    const raw = Buffer.from(rec.raw_hex || "", "hex");
    if (!raw.length) continue;
    const body = extractBody(raw);
    if (!body) continue;
    const opcode = "0x" + raw.subarray(0, 4).toString("hex");
    const direction = rec.direction || (f.startsWith("RECV") ? "RECV" : "SEND");
    const key = body.toString("hex");
    if (!index.has(key)) index.set(key, []);
    index.get(key).push({ opcode, direction });
    // Body yang diterima Unpack tidak menyertakan byte terminator 0x80 di
    // akhir amplop wire. Daftarkan juga varian tanpa byte terakhir agar
    // pencocokan tetap exact terhadap body hook.
    if (body.length > 1 && body[body.length - 1] === 0x80) {
      const key2 = body.subarray(0, body.length - 1).toString("hex");
      if (!index.has(key2)) index.set(key2, []);
      index.get(key2).push({ opcode, direction });
    }
  }

  // Kelompokkan per body unik. Body yang sama dapat muncul berkali-kali
  // (ping) atau cocok ke beberapa opcode (body sangat pendek/umum).
  const groups = new Map(); // bodyHex -> { className, hits:Set<"op|dir"> }
  let matched = 0;
  let unmatched = 0;
  for (const b of bodies) {
    if (!b.body_hex || b.body_hex.length < 10) continue; // < 5 byte: ambigu
    const hits = index.get(b.body_hex);
    if (!hits || !hits.length) {
      unmatched++;
      continue;
    }
    matched++;
    if (!groups.has(b.body_hex)) {
      groups.set(b.body_hex, { className: b.class_name, hits: new Set() });
    }
    const g = groups.get(b.body_hex);
    for (const h of hits) g.hits.add(h.opcode + "|" + h.direction);
  }

  // Suara hanya diberikan bila sebuah body unik menunjuk tepat satu opcode.
  // Body yang ambigu tidak dipakai supaya tidak mencemari hasil.
  const votes = new Map(); // opcode -> { direction, classes: Map<class,count>, sources:Set }
  let ambiguousBodies = 0;
  let strongBodies = 0;

  function vote(opcode, direction, className, source) {
    if (!votes.has(opcode))
      votes.set(opcode, { direction, classes: new Map(), sources: new Set() });
    const v = votes.get(opcode);
    v.classes.set(className, (v.classes.get(className) || 0) + 1);
    v.sources.add(source);
  }

  for (const [hex, g] of groups) {
    if (g.hits.size !== 1) {
      ambiguousBodies++;
      continue;
    }
    const [key] = g.hits;
    const sep = key.indexOf("|");
    const opcode = key.slice(0, sep);
    const direction = key.slice(sep + 1);
    vote(opcode, direction, g.className, "body");
    if (hex.length >= 32) strongBodies++; // >= 16 byte
  }

  // Bukti kedua: messageid ReturnMsg. DecodeMsgBody mencatat (opcode, msg_id)
  // dan Unpack mencatat (class_name, msg_id). Cocokkan lewat id yang sama.
  const msgids = readJsonl(path.join(DIR, "wire_msgids.jsonl"));
  const byMsg = new Map(); // msg_id -> Set(opcode)
  for (const m of msgids) {
    if (!m.msg_id || !m.opcode) continue;
    if (!byMsg.has(m.msg_id)) byMsg.set(m.msg_id, new Set());
    byMsg.get(m.msg_id).add(m.opcode);
  }
  let msgidPairs = 0;
  for (const b of bodies) {
    if (!b.msg_id || !b.class_name) continue;
    const ops = byMsg.get(b.msg_id);
    if (!ops || ops.size !== 1) continue;
    vote([...ops][0], "RECV", b.class_name, "msgid");
    msgidPairs++;
  }

  const out = [];
  for (const [opcode, v] of votes) {
    const ranked = [...v.classes.entries()].sort((a, b) => b[1] - a[1]);
    const [className, count] = ranked[0];
    const total = ranked.reduce((s, x) => s + x[1], 0);
    out.push({
      opcode,
      class_name: className,
      direction: v.sources.has("msgid") ? "RECV" : v.direction,
      votes: count,
      total,
      confidence: Number((count / total).toFixed(4)),
      sources: [...v.sources],
      alternatives: ranked.slice(1, 4).map(([name, n]) => ({ name, votes: n })),
    });
  }
  out.sort((a, b) => b.votes - a.votes || a.opcode.localeCompare(b.opcode));

  fs.writeFileSync(
    OUT,
    out.map((r) => JSON.stringify(r)).join("\n") + (out.length ? "\n" : ""),
  );

  console.log("[i] body sdp      : " + bodies.length);
  console.log("[i] paket wire    : " + files.length);
  console.log("[i] body cocok    : " + matched + " (ambigu: " + ambiguousBodies + ")");
  console.log("[i] body tak cocok: " + unmatched);
  console.log("[i] body kuat     : " + strongBodies + " (unik & >=16 byte)");
  console.log("[i] opcode unik   : " + out.length);
  console.log("[i] voting via msgid: " + msgidPairs);
  const strong = out.filter((r) => r.confidence === 1 && r.votes >= 2).length;
  console.log("[i] confidence=1 & votes>=2: " + strong);
  console.log("[✓] Ditulis ke " + OUT);
}

main();

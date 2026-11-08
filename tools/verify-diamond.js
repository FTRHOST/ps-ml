#!/usr/bin/env node
/**
 * verify-diamond.js — uji offline: pastikan override iDiamond dan iLevel
 * benar-benar terpasang pada frame role dari cache replay.
 *
 * Diperiksa:
 *   - Cmd_Role_Init_SC   : iDiamond (tag 11) dan iLevel (tag 3)
 *   - Cmd_Role_GetInfo_SC: iLevel (tag 3)
 *
 * Pemakaian:
 *   node tools/verify-diamond.js [diamond] [level]
 *   (default memakai DIAMOND/LEVEL dari server, yaitu state/profile.json)
 */
"use strict";

const sdp = require("../sdp");
const {
  REPLAY_CACHE,
  patchField,
  ROLE_INIT_SC,
  DIAMOND_TAG,
  LEVEL_TAG,
  ROLE_INFO_SC,
  DIAMOND,
  LEVEL,
} = require("../server");

const TARGET_DIAMOND = Number(process.argv[2] || DIAMOND);
const TARGET_LEVEL = Number(process.argv[3] || LEVEL);

function key(opcode) {
  return "0x" + opcode.toString(16);
}

/**
 * Cari nilai field: utamakan di dalam struct top-level (pola Cmd_Role_*),
 * fallback ke level teratas untuk body datar.
 */
function fieldValue(body, tag) {
  const nodes = sdp.decode(body);
  const isInt = (n) => n.type === sdp.T.INT || n.type === sdp.T.NEG;
  const struct = nodes.find((n) => n.type === sdp.T.STRUCT);
  if (struct) {
    const f = struct.fields.find((x) => x.tag === tag && isInt(x));
    if (f) return f.v;
  }
  const top = nodes.find((n) => n.tag === tag && isInt(n));
  return top ? top.v : undefined;
}

function show(value) {
  return value === undefined ? "(tidak ada)" : value.toString();
}

let failed = false;

// --- Cmd_Role_Init_SC: diamond + level ------------------------------------
const initEntry = REPLAY_CACHE.get(key(ROLE_INIT_SC));
if (!initEntry) {
  console.error("[!] Cmd_Role_Init_SC tidak ada di cache. Jalankan capture dulu.");
  failed = true;
} else {
  const before = initEntry.body;
  const after = patchField(
    patchField(before, DIAMOND_TAG, TARGET_DIAMOND),
    LEVEL_TAG,
    TARGET_LEVEL,
  );
  const d0 = fieldValue(before, DIAMOND_TAG);
  const d1 = fieldValue(after, DIAMOND_TAG);
  const l0 = fieldValue(before, LEVEL_TAG);
  const l1 = fieldValue(after, LEVEL_TAG);

  console.log(`[i] sumber          : ${initEntry.kind}`);
  console.log(`[i] body            : ${before.length} -> ${after.length} byte`);
  console.log(`[i] iDiamond (tag ${DIAMOND_TAG}) : ${show(d0)} -> ${show(d1)}`);
  console.log(`[i] iLevel   (tag ${LEVEL_TAG}) : ${show(l0)} -> ${show(l1)}`);

  if (d1 !== BigInt(TARGET_DIAMOND)) {
    console.error("[!] GAGAL: nilai iDiamond tidak terpasang.");
    failed = true;
  }
  if (l1 !== BigInt(TARGET_LEVEL)) {
    console.error("[!] GAGAL: nilai iLevel tidak terpasang di Cmd_Role_Init_SC.");
    failed = true;
  }
}

// --- Cmd_Role_GetInfo_SC: level -------------------------------------------
const infoEntry = REPLAY_CACHE.get(key(ROLE_INFO_SC));
if (!infoEntry) {
  console.error("[!] Cmd_Role_GetInfo_SC tidak ada di cache.");
  failed = true;
} else {
  const before = infoEntry.body;
  const after = patchField(before, LEVEL_TAG, TARGET_LEVEL);
  const l0 = fieldValue(before, LEVEL_TAG);
  const l1 = fieldValue(after, LEVEL_TAG);

  console.log(`[i] GetInfo body    : ${before.length} -> ${after.length} byte`);
  console.log(`[i] GetInfo iLevel  : ${show(l0)} -> ${show(l1)}`);

  if (l1 !== BigInt(TARGET_LEVEL)) {
    console.error("[!] GAGAL: nilai iLevel tidak terpasang di Cmd_Role_GetInfo_SC.");
    failed = true;
  }
}

if (failed) process.exit(1);
console.log(
  `[✓] Override iDiamond=${TARGET_DIAMOND} dan iLevel=${TARGET_LEVEL} valid.`,
);

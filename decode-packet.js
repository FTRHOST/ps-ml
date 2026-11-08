#!/usr/bin/env node
/**
 * MLBB Packet Decoder & Decompiler
 * Mendekompilasi binary packet (.bin) menjadi struktur SDP yang terbaca
 * dan otomatis menyimpan hasilnya ke file berakhiran .decom.
 *
 * Usage:
 *   node decode-packet.js <file.bin>
 *   node decode-packet.js relay-captures/c2-p4-S2C.bin
 */

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

// --- Opcode Map ---
const OPCODE_NAMES = {
  0x70000101: "Cmd_Login_Auth_CS",
  0x70000201: "Cmd_Login_Auth_SC",
  0x70000301: "Cmd_Login_GetZone_CS",
  0x70000401: "Cmd_Login_GetZone_SC",
  0x70000501: "Cmd_Login_CheckUpgrade_CS",
  0x70000601: "Cmd_Login_CheckUpgrade_SC",
  0x70000701: "Cmd_Login_GetBulletin_CS",
  0x70000801: "Cmd_Login_GetBulletin_SC",
  0x7000914e: "Cmd_Net_Connect_CS",
  0x7000924e: "Cmd_Net_Connect_SC",
};

// --- SDP Type Names ---
const SDP_TYPE_NAMES = {
  0: "Varint",
  1: "Int64 (8B fixed)",
  2: "Float (4B)",
  3: "Double (8B)",
  4: "String",
  5: "List",
  6: "Map",
  7: "StructBegin",
  8: "StructEnd",
};

// --- Varint helpers ---
function readVarUint(buf, pos) {
  let val = 0n;
  let shift = 0n;
  while (pos < buf.length) {
    const b = BigInt(buf[pos++]);
    val |= (b & 0x7fn) << shift;
    if (!(b & 0x80n)) break;
    shift += 7n;
  }
  return { val: Number(val), nextPos: pos };
}

// --- SDP Parser ---
function parseSDP(buf, offset, depth = 0, maxDepth = 10) {
  const indent = "  ".repeat(depth);
  const results = [];

  while (offset < buf.length && depth < maxDepth) {
    const b = buf[offset++];
    const typeCode = b >> 4;
    let tag = b & 0x0f;
    if (tag === 15) {
      if (offset >= buf.length) break;
      tag = buf[offset++];
    }

    const typeName = SDP_TYPE_NAMES[typeCode] || `Unknown(${typeCode})`;

    if (typeCode === 8) {
      // StructEnd
      results.push(`${indent}}} StructEnd`);
      break;
    }

    if (typeCode === 7) {
      // StructBegin
      results.push(`${indent}Tag ${tag}: StructBegin {{`);
      const inner = parseSDP(buf, offset, depth + 1, maxDepth);
      results.push(...inner.lines);
      offset = inner.nextPos;
      continue;
    }

    if (typeCode === 0) {
      // Varint
      const { val, nextPos } = readVarUint(buf, offset);
      results.push(
        `${indent}Tag ${tag}: ${typeName} = ${val} (0x${val.toString(16)})`,
      );
      offset = nextPos;
    } else if (typeCode === 1) {
      // Int64 (8B fixed, little-endian)
      if (offset + 8 <= buf.length) {
        const low = buf.readUInt32LE(offset);
        const high = buf.readUInt32LE(offset + 4);
        const val = BigInt(high) * 0x100000000n + BigInt(low);
        results.push(`${indent}Tag ${tag}: ${typeName} = ${val}`);
      }
      offset += 8;
    } else if (typeCode === 2) {
      // Float
      if (offset + 4 <= buf.length) {
        const val = buf.readFloatLE(offset);
        results.push(`${indent}Tag ${tag}: ${typeName} = ${val}`);
      }
      offset += 4;
    } else if (typeCode === 3) {
      // Double
      if (offset + 8 <= buf.length) {
        const val = buf.readDoubleLE(offset);
        results.push(`${indent}Tag ${tag}: ${typeName} = ${val}`);
      }
      offset += 8;
    } else if (typeCode === 4) {
      // String
      const { val: strLen, nextPos: strStart } = readVarUint(buf, offset);
      const strBuf = buf.subarray(strStart, strStart + strLen);
      let strVal;
      try {
        strVal = strBuf.toString("utf8");
        if (/[\x00-\x08\x0e-\x1f]/.test(strVal)) {
          strVal = `<hex: ${strBuf.toString("hex")}>`;
        }
      } catch {
        strVal = `<hex: ${strBuf.toString("hex")}>`;
      }
      results.push(`${indent}Tag ${tag}: ${typeName}(${strLen}) = "${strVal}"`);
      offset = strStart + strLen;
    } else if (typeCode === 5) {
      // List
      const { val: count, nextPos } = readVarUint(buf, offset);
      results.push(`${indent}Tag ${tag}: List(${count}) [`);
      offset = nextPos;
      for (let i = 0; i < count && offset < buf.length; i++) {
        const inner = parseSDP(buf, offset, depth + 1, maxDepth);
        results.push(...inner.lines);
        offset = inner.nextPos;
      }
      results.push(`${indent}]`);
    } else if (typeCode === 6) {
      // Map
      const { val: count, nextPos } = readVarUint(buf, offset);
      results.push(`${indent}Tag ${tag}: Map(${count}) {`);
      offset = nextPos;
      for (let i = 0; i < count && offset < buf.length; i++) {
        const kInner = parseSDP(buf, offset, depth + 1, maxDepth);
        results.push(...kInner.lines);
        offset = kInner.nextPos;
        const vInner = parseSDP(buf, offset, depth + 1, maxDepth);
        results.push(...vInner.lines);
        offset = vInner.nextPos;
      }
      results.push(`${indent}}`);
    } else {
      results.push(`${indent}Tag ${tag}: ${typeName} (skipped)`);
      break;
    }
  }

  return { lines: results, nextPos: offset };
}

// --- Main ---
function decodePacket(filePath) {
  let raw = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);
  const logOutput = [];

  const log = (msg = "") => {
    console.log(msg);
    logOutput.push(msg);
  };

  log("=".repeat(70));
  log(`  MLBB Packet Decoder: ${fileName}`);
  log(`  File size: ${raw.length} bytes`);
  log("=".repeat(70));

  // Auto-detect Zstd compressed packet
  let isZstd = false;
  if (
    raw.length >= 8 &&
    raw.readUInt16BE(0) === 0x1000 &&
    raw.readUInt32BE(4) === 0x28b52ffd
  ) {
    isZstd = true;
    log(`\n[*] Terdeteksi: Paket Zstd Compressed`);
    const totalLen = (raw[2] << 8) | raw[3];
    log(`[*] Frame Header: 0x1000 | Total Len: ${totalLen}`);

    const zstdData = raw.subarray(4);
    try {
      const decomp = cp.execFileSync("zstd", ["-d", "-q"], { input: zstdData });
      log(`[*] Decompressed: ${zstdData.length}B -> ${decomp.length}B`);
      raw = decomp;
    } catch (e) {
      log(`[!] Gagal dekompresi Zstd: ${e.message}`);
      return;
    }
  }

  let opcode, seq, envelopeStart;

  if (!isZstd && raw.length >= 8) {
    const totalLen = raw.readUInt32BE(0);
    const maybeOpcode = raw.readUInt32BE(4);

    if ((maybeOpcode & 0x70000000) === 0x70000000) {
      opcode = maybeOpcode;
      seq = raw[8];
      envelopeStart = 9;
      log(`\n[*] Format: Standard Uncompressed`);
      log(
        `[*] TotalLen: ${totalLen} | Opcode: 0x${opcode.toString(16)} (${OPCODE_NAMES[opcode] || "Unknown"}) | Seq: 0x${seq.toString(16)}`,
      );
    } else {
      opcode = raw.readUInt32BE(0);
      seq = raw[4];
      envelopeStart = 5;
      log(`\n[*] Format: Decompressed (no TotalLen header)`);
      log(
        `[*] Opcode: 0x${opcode.toString(16)} (${OPCODE_NAMES[opcode] || "Unknown"}) | Seq: 0x${seq.toString(16)}`,
      );
    }
  } else {
    opcode = raw.readUInt32BE(0);
    seq = raw[4];
    envelopeStart = 5;
    log(
      `\n[*] Opcode: 0x${opcode.toString(16)} (${OPCODE_NAMES[opcode] || "Unknown"}) | Seq: 0x${seq.toString(16)}`,
    );
  }

  let sdpStart;
  const envByte = raw[envelopeStart];

  if (envByte === 0x45 || envByte === 0x46) {
    const dir = envByte === 0x45 ? "Client->Server" : "Server->Client";
    const { val: sdpLen, nextPos } = readVarUint(raw, envelopeStart + 1);
    sdpStart = nextPos;
    log(`[*] Envelope: LOGIN (${dir}) | SDP Len: ${sdpLen + 1}`);
  } else if (
    raw[envelopeStart + 1] === 0x02 &&
    raw[envelopeStart + 2] === 0x00 &&
    raw[envelopeStart + 3] === 0x05 &&
    raw[envelopeStart + 4] === 0x00 &&
    raw[envelopeStart + 5] === 0x46
  ) {
    const rspCode = raw[envelopeStart];
    const { val: sdpLen, nextPos } = readVarUint(raw, envelopeStart + 6);
    sdpStart = nextPos;
    log(
      `[*] Envelope: GAME | RspCode: 0x${rspCode.toString(16)} | SDP Len: ${sdpLen + 1}`,
    );
  } else {
    log(`[*] Envelope: Unknown pattern (byte: 0x${envByte.toString(16)})`);
    log(
      `[*] Raw bytes envelope: ${raw.subarray(envelopeStart, envelopeStart + 10).toString("hex")}`,
    );
    sdpStart = envelopeStart;
  }

  // Parse SDP body
  log(
    `\n--- SDP Body (offset ${sdpStart}, ${raw.length - sdpStart} bytes) ---\n`,
  );
  const { lines } = parseSDP(raw, sdpStart, 0);
  for (const line of lines) {
    log(line);
  }

  // Raw hex dump
  log(`\n--- Raw Hex Dump (first 128 bytes) ---`);
  const hexLimit = Math.min(raw.length, 128);
  for (let i = 0; i < hexLimit; i += 16) {
    const slice = raw.subarray(i, Math.min(i + 16, hexLimit));
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    log(`  ${i.toString(16).padStart(4, "0")}: ${hex.padEnd(48)}| ${ascii}`);
  }

  // Simpan hasil ke file .decom
  const outputFileName = filePath + ".decomp";
  fs.writeFileSync(outputFileName, logOutput.join("\n"), "utf8");
  console.log(`\n[✔] Berhasil disimpan ke: ${outputFileName}`);
}

// --- CLI ---
const args = process.argv.slice(2);
if (args.length === 0) {
  console.log("Usage: node decode-packet.js <file.bin> [file2.bin] ...");
  process.exit(1);
}

for (const filePath of args) {
  if (fs.existsSync(filePath)) {
    decodePacket(filePath);
  } else {
    console.error(`[!] File tidak ditemukan: ${filePath}`);
  }
}

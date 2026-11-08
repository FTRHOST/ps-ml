#!/usr/bin/env node
/**
 * Test round-trip SDP.
 *   node test-sdp.js                       -> vektor bawaan (data asli dari auth-server.js)
 *   node test-sdp.js relay-captures/*.bin  -> semua capture: decode -> encode harus identik
 *   node test-sdp.js -v file.bin           -> tampilkan juga pohon hasil decode
 */
const fs = require("fs");
const path = require("path");
const sdp = require("./sdp");

let pass = 0, fail = 0;
function check(name, ok, info = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info ? "  " + info : ""}`);
  ok ? pass++ : fail++;
}

function roundTripBody(name, body, verbose) {
  try {
    const nodes = sdp.decode(body);
    if (verbose) console.log(sdp.toText(nodes) + "\n");
    const again = sdp.encode(nodes);
    const ok = again.equals(body);
    check(`body ${name}`, ok, ok ? `(${body.length}B)` : `\n   asli : ${body.toString("hex")}\n   ulang: ${again.toString("hex")}`);
  } catch (e) {
    check(`body ${name}`, false, e.message);
  }
}

function roundTripFrame(name, buf, verbose) {
  try {
    const f = sdp.parseFrame(buf);
    if (verbose) console.log(`opcode=0x${f.opcode.toString(16)} seq=${f.seq} env=${f.envelope}`);
    roundTripBody(name, f.body, verbose);
    // hdr asli diteruskan supaya format header apa pun (lama/baru) kembali identik
    check(`frame ${name}`, sdp.buildFrame(f.opcode, f.seq, f.body, f.envelope, f.hdr).equals(buf));
  } catch (e) {
    check(`frame ${name}`, false, e.message);
  }
}

const args = process.argv.slice(2);
const verbose = args[0] === "-v";
const files = args.filter((a) => a !== "-v");

if (files.length === 0) {
  // 1) Bulletin SC asli (dari auth-server.js)
  const bulletin = Buffer.from(
    "cFABcACj0dQJQQ9VUERBVEUgUkVRVUlSRURClwJbZmY1MDUwXVRoaXMgRnlyZWZseTIxIGFwcCBpcyB0b28gb2xkLlstXQpbZmZkMDQwXUluc3RhbGwgdGhlIG5ldyBGeXJlZmx5MjEgdG8ga2VlcCBwbGF5aW5nLiBZb3VyIGFjY291bnQgc3RheXMuWy1dCgpEb3dubG9hZCBpdCBmcm9tIFs2MGZmNjBdMjEuZnlyZWZseS5teS5pZFstXSwgb3Igb3BlbiBbNjBmZjYwXUZseVBsYXlbLV0gYW5kIHRhcCBbNjBmZjYwXVVwZGF0ZVstXS4KCkFscmVhZHkgdXBkYXRlZD8gQ2xvc2UgdGhlIGdhbWUgY29tcGxldGVseSBhbmQgb3BlbiBpdCBhZ2Fpbi4DwIQ9BACAgIA=",
    "base64"
  );
  roundTripBody("bulletin-sc (asli)", bulletin, true);
  roundTripFrame("bulletin-sc framed", sdp.buildFrame(0x70000801, 1, bulletin), false);

  // 2) Cold-start reject asli 12 byte (c1-p2-S2C.bin)
  const reject = Buffer.from("0000000c70000201" + "01" + "152d" + "80", "hex");
  roundTripFrame("cold-start reject -45 (asli)", reject, true);
  const rej = sdp.parseFrame(reject);
  const n = sdp.decode(rej.body);
  check("reject = int -45 di tag 5", n[0].tag === 5 && n[0].v === -45n);

  // 3) Builder -> decoder (konsistensi encoder)
  const body = sdp.buildBody([
    sdp.node.int(0, 99999999), sdp.node.str(1, "sesi"), sdp.node.int(5, -45),
    sdp.node.list(20, [sdp.node.struct(0, [sdp.node.int(0, 57102), sdp.node.str(7, "ID")])]),
    sdp.node.float(30, 1.5), sdp.node.int(40, 1793530475),
  ]);
  roundTripBody("builder sintetis (tag>=15, list struct, negatif)", body, true);
} else {
  // Artefak "-unknown-" adalah byte non-protokol (mis. laporan teks login) yang
  // memang tidak bisa di-round-trip; bukan frame SDP, jadi tidak diuji.
  let skipped = 0;
  for (const f of files) {
    if (path.basename(f).includes("-unknown-")) {
      skipped++;
      continue;
    }
    roundTripFrame(f, fs.readFileSync(f), verbose);
  }
  if (skipped) console.log(`[i] ${skipped} file non-protokol (-unknown-) dilewati`);
}

console.log(`\n${pass} lulus, ${fail} gagal`);
process.exit(fail ? 1 : 0);

const net = require("net");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

// Fixture: capture zstd asli dari proyek lama (di-gitignore, bukan bagian repo).
const FIXTURE = process.env.RELAY_FIXTURE_DIR || "/home/petwirkepo/ps2-mlbb/relay-captures";
const sdp = require("./sdp");

const UP_PORT = 39999, RL_PORT = 39998;
let pass = 0, fail = 0;
const check = (n, ok, info="") => { console.log(`${ok?"PASS":"FAIL"}  ${n} ${info}`); ok?pass++:fail++; };

// upstream palsu: catat byte masuk, balas byte identik (echo)
const seenUp = [];
const up = net.createServer(s => { s.on("data", d => { seenUp.push(Buffer.from(d)); s.write(d); }); });

function frame(op, seq, body) { return sdp.buildFrame(op, seq, body, "game-cs"); }
const body1 = sdp.buildBody([sdp.node.int(0, 123), sdp.node.str(1, "halo")]);
const body2 = sdp.buildBody([sdp.node.int(5, -45)]);
const f1 = frame(0x70000101, 1, body1);
const f2 = frame(0x70000701, 2, body2);
// payload zstd ASLI dari capture cold-start (683B) supaya dekompress benar-benar diuji;
// bila file fixture eksternal belum ada, gunakan payload sintetis zstd yang valid
let zstdProbe;
const fixtureBin = path.join(FIXTURE, "auth-server-c1-p1-S2C.bin");
if (fs.existsSync(fixtureBin)) {
  zstdProbe = fs.readFileSync(fixtureBin);
} else {
  const zlib = require("zlib");
  const innerPayload = Buffer.concat([
    Buffer.from("70000201", "hex"), // opcode Cmd_Login_Auth_SC
    Buffer.from([0x01]),             // seq 1
    Buffer.from([0x01]),             // extra byte
    Buffer.from([0x46]),             // s2c magic
    sdp.writeVarUint(body2.length - 1),
    body2,
  ]);
  const compressed = zlib.zstdCompressSync(innerPayload);
  const head = Buffer.alloc(4);
  head[0] = 0x10;
  head[1] = 0x00;
  head.writeUInt16BE(4 + compressed.length, 2);
  zstdProbe = Buffer.concat([head, compressed]);
}

up.listen(UP_PORT, "127.0.0.1", () => {
  const relay = cp.spawn("node", ["relay.js"], {
    env: { ...process.env, AUTH_PORT: String(RL_PORT), AUTH_UPSTREAM: `127.0.0.1:${UP_PORT}`,
           ZONE_PORT: "39997", ZONE_UPSTREAM: `127.0.0.1:${UP_PORT}`, HOST: "127.0.0.1" },
    stdio: ["ignore","pipe","pipe"] });
  relay.stdout.on("data", d => process.stdout.write("  [relay] " + d));
  relay.stderr.on("data", d => process.stdout.write("  [relay!] " + d));

  setTimeout(() => {
    const c = net.connect(RL_PORT, "127.0.0.1", () => {
      // kirim: 2 frame menempel, lalu 1 frame terpecah 2 bagian, lalu probe zstd
      const joined = Buffer.concat([f1, f2]);
      c.write(joined.subarray(0, 10));              // sebagian
      setTimeout(() => {
        c.write(joined.subarray(10));               // sisanya
        c.write(f2.subarray(0, 5));                 // frame terpecah
        setTimeout(() => {
          c.write(f2.subarray(5));
          c.write(zstdProbe);
        }, 60);
      }, 60);
    });
    let got = Buffer.alloc(0);
    c.on("data", d => got = Buffer.concat([got, d]));

    setTimeout(() => {
      // upstream men-echo seluruh byte yang diterima, jadi client menerima
      // kembali persis byte yang dikirim: f1+f2 (menempel) + f2 (terpecah) + probe
      const expectAll = Buffer.concat([f1, f2, f2, zstdProbe]);
      check("passthrough byte-identik (client terima kembali)", got.equals(expectAll), `got=${got.length} exp=${expectAll.length}`);
      check("upstream menerima byte identik", Buffer.concat(seenUp).equals(expectAll), `up=${Buffer.concat(seenUp).length}`);

      // periksa capture
      const dirs = fs.readdirSync("captures");
      const latest = dirs[dirs.length-1];
      const dir = path.join("captures", latest);
      const bins = fs.readdirSync(dir).filter(f => f.endsWith(".bin"));
      const zstds = fs.readdirSync(dir).filter(f => f.endsWith(".zstd"));
      const jsons = fs.readdirSync(dir).filter(f => f.endsWith(".json") && f !== "frames.jsonl");
      check("frame .bin tersimpan (3 c2s + 3 s2c di-echo)", bins.length === 6, `bins=${bins.length} (${bins.join(", ")})`);
      check("probe zstd tersimpan .zstd (c2s+s2c)", zstds.length === 2, `zstd=${zstds.length}`);
      check("metadata json per frame", jsons.length === 8, `json=${jsons.length}`);
      console.log("   nama file:", [...bins, ...zstds].sort().join(" | "));

      // round-trip test-sdp atas capture .bin
      const t = cp.spawnSync("node", ["test-sdp.js", ...bins.map(b=>path.join(dir,b))], {encoding:"utf8"});
      check("test-sdp.js atas capture .bin 100% lulus", t.status === 0, t.stdout.trim().split("\n").pop());

      // metadata sanity
      const metas = jsons.map(f => JSON.parse(fs.readFileSync(path.join(dir,f))));
      check("metadata punya waktu/panjang/seq", metas.every(m => m.timestamp && m.length > 0 && m.seq > 0));
      check("opcode + nama tercatat", metas.some(m => m.opcode === "0x70000101" && m.opcode_name === "Cmd_Login_Auth_CS"),
            JSON.stringify(metas.map(m=>m.opcode)));

      const zm = metas.filter(m => m.kind === "zstd");
      check("probe zstd terdekomposisi -> opcode terbaca", zm.length === 2 && zm.every(m => m.opcode),
            JSON.stringify(zm.map(m => m.opcode)));

      relay.kill(); up.close();
      console.log(`\n${pass} lulus, ${fail} gagal`);
      process.exit(fail ? 1 : 0);
    }, 700);
  }, 500);
});

const net = require("net");
const fs = require("fs");
const path = require("path");

/**
 * MLBB Standalone Server
 * 1. Port 30021 : Auth & Upgrade Server
 *    - Menangani Cold Start probe (0x1000) dengan error code resmi -45 (Session Expired),
 *      sehingga game client tidak loop dan langsung lanjut ke Full Login (0x70000101).
 *    - Menggunakan konfigurasi CDN resmi dari Moonton (akmcdn.ml.youngjoygame.com).
 *    - sConnServer diarahkan ke Zone Port lokal 30101.
 * 2. Port 30101 : Zone / Lobby Server
 *    - Menangani handshake koneksi game 0x7000914e -> membalas 0x7000924e (Cmd_Net_Connect_SC).
 */

const AUTH_PORT = 30021;
const ZONE_PORT = 30101;
const HOST = "0.0.0.0";
const SERVER_IP = process.env.SERVER_IP || "0.0.0.0";

const CAPTURE_DIR = path.join(__dirname, "relay-captures");
if (!fs.existsSync(CAPTURE_DIR)) {
  fs.mkdirSync(CAPTURE_DIR, { recursive: true });
}

// --- SDP HELPER (Standard Moonton SDP/Tars Encoding) ---
function writeVarUint(val) {
  let v = BigInt(val);
  const bytes = [];
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) b |= 0x80;
    bytes.push(b);
  } while (v !== 0n);
  return Buffer.from(bytes);
}

function writeTag(tag, typeCode) {
  if (tag < 15) {
    return Buffer.from([(typeCode << 4) | tag]);
  } else {
    return Buffer.from([(typeCode << 4) | 15, tag]);
  }
}

function packString(tag, str) {
  const sBuf = Buffer.from(str || "", "utf8");
  const tagBuf = writeTag(tag, 4); // Type 4: String
  return Buffer.concat([tagBuf, writeVarUint(sBuf.length), sBuf]);
}

function packInt(tag, val) {
  const tagBuf = writeTag(tag, 0); // Type 0: Positive Varint
  return Buffer.concat([tagBuf, writeVarUint(val)]);
}

function packPacket(opcode, seq, sdpBody) {
  const magic = Buffer.from([0x05, 0x00, 0x46]);
  // Aturan varint panjang paket SDP = sdpBody.length - 1
  const lenVarint = writeVarUint(sdpBody.length - 1);

  const payload = Buffer.concat([
    Buffer.from([seq, 0x02, 0x00]),
    magic,
    lenVarint,
    sdpBody,
  ]);

  const totalLen = payload.length + 8;
  const frameHeader = Buffer.alloc(8);
  frameHeader.writeUInt32BE(totalLen, 0);
  frameHeader.writeUInt32BE(opcode, 4);

  return Buffer.concat([frameHeader, payload]);
}

// ----------------------------------------------------
// 1. AUTH & CHECKUPGRADE (PORT 30021)
// ----------------------------------------------------

/**
 * Paket resmi penolak Cold Start (Session Expired: error -45)
 * Format terkonfirmasi dari c1-p2-S2C.bin (12 byte):
 * 00 00 00 0c (len 12) + 70 00 02 01 (Cmd_Login_Auth_SC) + 01 (seq 1) + 15 2d 80 (err -45)
 */
function buildColdStartReject(seq = 0x01) {
  const frame = Buffer.alloc(12);
  frame.writeUInt32BE(12, 0); // Total length: 12 bytes
  frame.writeUInt32BE(0x70000201, 4); // Opcode: Cmd_Login_Auth_SC
  frame[8] = seq; // Sequence number
  frame[9] = 0x15; // Type 1 (Negative Integer), Tag 5
  frame[10] = 0x2d; // Varint 45 -> Nilai: -45
  frame[11] = 0x80; // StructEnd
  return frame;
}

function buildLoginAuthSC(
  seq,
  accountId = 99999999,
  zoneId = 57102,
  zoneName = "petwirkepo",
) {
  const sdpParts = [];
  sdpParts.push(Buffer.from([0x70])); // StructBegin

  // Tag 0: iAccountId
  sdpParts.push(packInt(0, accountId));

  // Tag 1: sSessionKey
  const sessionKey = "fs3c9d921a6cfd44c62259f88f";
  sdpParts.push(packString(1, sessionKey));

  // Tag 2: stZone (CmdZoneInfo)
  sdpParts.push(
    Buffer.concat([
      Buffer.from([0x72]), // StructBegin dengan Tag 2 (0x70 | 2)
      packInt(0, zoneId),
      packString(1, zoneName),
      packInt(2, 1),
      Buffer.from([0x80]), // StructEnd
    ]),
  );

  // Tag 3: vAccountInfo (List kosong)
  sdpParts.push(Buffer.from([0x53, 0x00]));

  // Tag 10: iServerTimeMS
  sdpParts.push(packInt(10, BigInt(Date.now())));

  // Tag 11 - 14
  sdpParts.push(packInt(11, 0)); // bLocalZoneHasMerged
  sdpParts.push(packInt(12, 1)); // bNewAccount
  sdpParts.push(packInt(13, 2)); // iAccountFlag
  sdpParts.push(packInt(14, 0)); // uiCreateAlt

  // Tag 19: iAccCreateTime
  sdpParts.push(packInt(19, 1793530475));

  // --- TAG 20: vSimpleRoleInfo (List berisi 1 Karakter dengan aman) ---
  const roleItem = Buffer.concat([
    Buffer.from([0x70]), // StructBegin untuk SimpleRoleInfo
    packInt(0, zoneId), // Tag 0: iZoneID
    packInt(1, 1793530475), // Tag 1: iCreateRoleTime
    packInt(2, 0), // Tag 2: iAreaTag
    packInt(3, 1), // Tag 3: bChangeName
    packInt(4, 4), // Tag 4: iCreateRoleAreaTag
    packInt(5, 999), // Tag 5: iLevel (Misal: Level 1)
    packInt(6, 0), // Tag 6: iForceChangeAreaTagReason
    packString(7, "ID"), // Tag 7: sCreateRoleCountry

    // vABTestExpParam (List kosong di dalam struct: Type 5, Tag 8)
    Buffer.concat([writeTag(8, 5), Buffer.from([0x00])]),

    Buffer.from([0x80]), // StructEnd untuk SimpleRoleInfo
  ]);

  // Menggabungkan ke Tag 20 menggunakan helper writeTag(20, 5) [Type 5 = List]
  // Format List: [Header Tag, Jumlah Item, Data Item...]
  const tag20Header = writeTag(20, 5); // Otomatis menangani tag >= 15 dengan benar
  sdpParts.push(
    Buffer.concat([
      tag20Header,
      Buffer.from([0x01]), // Jumlah item di dalam list (1 buah karakter)
      roleItem,
    ]),
  );

  sdpParts.push(Buffer.from([0x80, 0x80])); // StructEnd utama
  return packPacket(0x70000201, seq, Buffer.concat(sdpParts));
}

const BULLETIN_SDP_TEMPLATE = Buffer.from(
  "cFABcACj0dQJQQ9VUERBVEUgUkVRVUlSRURClwJbZmY1MDUwXVRoaXMgRnlyZWZseTIxIGFwcCBpcyB0b28gb2xkLlstXQpbZmZkMDQwXUluc3RhbGwgdGhlIG5ldyBGeXJlZmx5MjEgdG8ga2VlcCBwbGF5aW5nLiBZb3VyIGFjY291bnQgc3RheXMuWy1dCgpEb3dubG9hZCBpdCBmcm9tIFs2MGZmNjBdMjEuZnlyZWZseS5teS5pZFstXSwgb3Igb3BlbiBbNjBmZjYwXUZseVBsYXlbLV0gYW5kIHRhcCBbNjBmZjYwXVVwZGF0ZVstXS4KCkFscmVhZHkgdXBkYXRlZD8gQ2xvc2UgdGhlIGdhbWUgY29tcGxldGVseSBhbmQgb3BlbiBpdCBhZ2Fpbi4DwIQ9BACAgIA=",
  "base64",
);

function buildLoginGetBulletinSC(seq) {
  return packPacket(0x70000801, seq, BULLETIN_SDP_TEMPLATE);
}

/**
 * Cmd_Login_CheckUpgrade_SC dengan CDN Asli Moonton
 * Mengarahkan sConnServer ke port Zone 30101
 */
function buildLoginCheckUpgradeSC(
  seq,
  connServer = `${SERVER_IP}:${ZONE_PORT}`,
) {
  const sdpParts = [];
  sdpParts.push(Buffer.from([0x70])); // StructBegin

  // Tag 0: iZoneId = 57102
  sdpParts.push(packInt(0, 57102));

  // Tag 1: sConnServer (diarahkan ke zone port kita)
  sdpParts.push(packString(1, connServer));

  // Tag 2: sClientVersion = 2.2.16.1235.1
  sdpParts.push(packString(2, "2.2.30.1250.1"));

  // Tag 3: sResPatchVersion = ""
  sdpParts.push(packString(3, ""));

  // Tag 4: sResAllVersion = ""
  sdpParts.push(packString(4, ""));

  // Tag 5: sCdnVersion = "1"
  sdpParts.push(packString(5, "1"));

  // Tag 6: sApkUpdateAddr
  sdpParts.push(packString(6, "https://www.taptap.io/app/33653913"));

  // Tag 7: sForceVersion = "2.2.29"
  sdpParts.push(packString(7, "2.1.0"));

  // Tag 8: sFaceCdnHost = ""
  sdpParts.push(packString(8, ""));

  // Tag 11: sResPatchVersionNew (CDN resmi Moonton)
  const patchUrls =
    "http://akmcdn.ml.youngjoygame.com/res_patch/;http://akmcdn.ml.youngjoygame.com/res_patch/;http://pldtcdn.ml.youngjoygame.com/res_patch/;http://wscdn.ml.youngjoygame.com/res_patch/";
  sdpParts.push(packString(11, patchUrls));

  // Tag 12: sResAllVersionNew (CDN resmi Moonton)
  const allUrls =
    "http://akmcdn.ml.youngjoygame.com/res_version/;http://akmcdn.ml.youngjoygame.com/res_version/;http://pldtcdn.ml.youngjoygame.com/res_version/;http://wscdn.ml.youngjoygame.com/res_version/";
  sdpParts.push(packString(12, allUrls));

  // Tag 13: sNewConnServerList
  sdpParts.push(packString(13, `${connServer};8.219.169.192:30102`));

  // Tag 14: iRetryNum = 3
  sdpParts.push(packInt(14, 3));

  // Tag 15: sSignature
  sdpParts.push(
    packString(
      15,
      "d659c5397a8f2a5b6f3489e546a389ca54fd28fc,eda6413c3e3a95492114fe07cd953ad897e40d1a",
    ),
  );

  // Tag 17: sForceUpdateUrl
  sdpParts.push(packString(17, "https://www.taptap.io/app/33653913"));

  // Tag 27: bFixCheckUpgrade = true (1)
  sdpParts.push(packInt(27, 1));

  sdpParts.push(Buffer.from([0x80, 0x80])); // StructEnd x2

  const sdpBody = Buffer.concat(sdpParts);
  return packPacket(0x70000601, seq, sdpBody);
}

// ----------------------------------------------------
// 2. ZONE SERVER (PORT 30101)
// ----------------------------------------------------

/**
 * Cmd_Net_Connect_SC (0x7000924e)
 * Menjawab handshake in-game dari client
 */
function buildNetConnectSC(seq, sessionKey = "fs3c9d921a6cfd44c62259f88f") {
  const sdpParts = [];
  sdpParts.push(Buffer.from([0x70])); // StructBegin

  // Tag 0: sNewSessionKey (String)
  sdpParts.push(packString(0, sessionKey));

  // Tag 1: iExchangeInterval = 3600 (UInt32)
  sdpParts.push(packInt(1, 3600));

  sdpParts.push(Buffer.from([0x80, 0x80])); // StructEnd x2

  const sdpBody = Buffer.concat(sdpParts);
  return packPacket(0x7000924e, seq, sdpBody);
}

// --- SERVER LISTENERS ---

const authServer = net.createServer((sock) => {
  const clientAddr = `${sock.remoteAddress}:${sock.remotePort}`;
  console.log(`\n[AUTH:30021] Klien terhubung dari: ${clientAddr}`);

  let buffer = Buffer.alloc(0);

  sock.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 4) {
      const magicHead = buffer.readUInt16BE(0);

      // Tangani Cold Start Handshake Probe (0x1000)
      if (magicHead === 0x1000) {
        console.log(
          `[AUTH:30021] Cold Start probe 0x1000 (${buffer.length}B) terdeteksi.`,
        );
        console.log(
          `[AUTH:30021] Mengirim balasan resmi Session Expired (-45) agar game langsung Full Login...`,
        );
        const rejectPkt = buildColdStartReject(0x01);
        sock.write(rejectPkt, () => {
          sock.end();
        });
        return;
      }

      if (buffer.length < 8) break;

      const packetLen = buffer.readUInt32BE(0);
      if (buffer.length < packetLen) break;

      const packet = buffer.subarray(0, packetLen);
      buffer = buffer.subarray(packetLen);

      const opcode = packet.readUInt32BE(4);
      const hexOpcode = "0x" + opcode.toString(16);
      const seq = packet.length > 8 ? packet[8] : 0x01;

      console.log(
        `[AUTH:30021] RECV: ${packetLen}B | Opcode: ${hexOpcode} | Seq: 0x${seq.toString(16)}`,
      );

      if (opcode === 0x70000101) {
        console.log(
          `[AUTH:30021] 1/3: Cmd_Login_Auth_CS -> Mengirim Cmd_Login_Auth_SC (81B)...`,
        );
        sock.write(buildLoginAuthSC(seq));
      } else if (opcode === 0x70000701) {
        console.log(
          `[AUTH:30021] 2/3: Cmd_Login_GetBulletin_CS -> Mengirim Cmd_Login_GetBulletin_SC (333B)...`,
        );
        sock.write(buildLoginGetBulletinSC(seq));
      } else if (opcode === 0x70000501) {
        console.log(
          `[AUTH:30021] 3/3: Cmd_Login_CheckUpgrade_CS -> Mengirim CheckUpgrade CDN Resmi Moonton...`,
        );
        sock.write(buildLoginCheckUpgradeSC(seq, `${SERVER_IP}:${ZONE_PORT}`));
      }
    }
  });

  sock.on("close", () =>
    console.log(`[AUTH:30021] Klien terputus (${clientAddr})`),
  );
  sock.on("error", (err) => console.error(`[AUTH:30021] Error:`, err.message));
});

const zoneServer = net.createServer((sock) => {
  const clientAddr = `${sock.remoteAddress}:${sock.remotePort}`;
  console.log(
    `\n=============================================================`,
  );
  console.log(`[ZONE:30101] [+] KLIEN IN-GAME TERHUBUNG DARI: ${clientAddr}`);
  console.log(`=============================================================`);

  let buffer = Buffer.alloc(0);

  sock.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 8) {
      const packetLen = buffer.readUInt32BE(0);
      if (buffer.length < packetLen) break;

      const packet = buffer.subarray(0, packetLen);
      buffer = buffer.subarray(packetLen);

      const opcode = packet.readUInt32BE(4);
      const hexOpcode = "0x" + opcode.toString(16);
      const seq = packet.length > 8 ? packet[8] : 0x01;

      console.log(
        `\n[ZONE:30101] RECV: ${packetLen}B | Opcode: ${hexOpcode} | Seq: 0x${seq.toString(16)}`,
      );

      if (opcode === 0x7000914e) {
        console.log(
          `[ZONE:30101] Handshake Game Connect terdeteksi! Membalas Cmd_Net_Connect_SC (0x7000924e)...`,
        );
        const resp = buildNetConnectSC(seq);
        sock.write(resp);
        console.log(
          `[ZONE:30101] Terkirim Cmd_Net_Connect_SC (${resp.length}B)`,
        );
      } else if (opcode === 0x7000954e) {
        const sdpBody = Buffer.from([0x70, 0x80, 0x80]);
        const heartbeatResp = packPacket(0x7000954e, seq, sdpBody);
        sock.write(heartbeatResp);
      } else {
        const sdpBody = Buffer.from([0x70, 0x80, 0x80]);
        const echoResp = packPacket(opcode, seq, sdpBody);
        sock.write(echoResp);
      }
    }
  });

  sock.on("close", () =>
    console.log(`[ZONE:30101] [-] Klien terputus (${clientAddr})`),
  );
  sock.on("error", (err) => console.error(`[ZONE:30101] Error:`, err.message));
});

function startAuthServer() {
  return new Promise((resolve) => {
    authServer.listen(AUTH_PORT, HOST, () => {
      console.log(`====================================================`);
      console.log(`   MLBB Standalone Server Aktif!`);
      console.log(`   Port Auth : ${AUTH_PORT}`);
      console.log(`   Port Zone : ${ZONE_PORT}`);
      console.log(`   Server IP : ${SERVER_IP}`);
      console.log(`   ColdStart : Handled (-45 Session Expired)`);
      console.log(`   CDN Mode  : Official Moonton CDN`);
      console.log(`====================================================\n`);
      resolve();
    });
  });
}

function startZoneServer() {
  return new Promise((resolve) => {
    zoneServer.listen(ZONE_PORT, HOST, () => resolve());
  });
}

module.exports = {
  AUTH_PORT,
  ZONE_PORT,
  HOST,
  SERVER_IP,
  startAuthServer,
  startZoneServer,
  buildColdStartReject,
  buildLoginAuthSC,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  buildNetConnectSC,
  packPacket,
};

if (require.main === module) {
  startAuthServer().then(() => startZoneServer());
}

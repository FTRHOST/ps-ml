const net = require("net");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const sdp = require("./sdp");
const { DatabaseSync } = require("node:sqlite");

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

// ----------------------------------------------------
// 2b. LOGIN AUTH (Cmd_Login_Auth_CS -> Cmd_Login_Auth_SC)
// ----------------------------------------------------

/**
 * Peta field MsgCmd_Login_Auth_CS -> nomor tag SDP.
 * Field pertama di dump.cs (sAccountName, offset 0x10) memakai tag 0 dan
 * nomor tag naik satu per field declaration. Tipe: 4 = string, 0 = int,
 * 7 = struct; bool disimpan sebagai int.
 */
const CS_TAG_FIELDS = [
  { tag: 0, field: "sAccountName", type: "string" },
  { tag: 1, field: "sAuthKey", type: "string" },
  { tag: 2, field: "sClientVersion", type: "string" },
  { tag: 3, field: "sChannel", type: "string" },
  { tag: 4, field: "sOSLanguage", type: "string" },
  { tag: 5, field: "iOSType", type: "int" },
  { tag: 6, field: "mMiscData", type: "string" },
  { tag: 7, field: "iLocalZoneId", type: "int" },
  { tag: 8, field: "iRegionId", type: "int" },
  { tag: 9, field: "sCountry", type: "string" },
  { tag: 10, field: "sUserIP", type: "string" },
  { tag: 11, field: "uiCreateAlt", type: "int" },
  { tag: 12, field: "uiConfirmNotOverrideFromZing", type: "int" },
  { tag: 13, field: "sUnityVersion", type: "string" },
  { tag: 14, field: "sDeviceInfo", type: "string" },
  { tag: 15, field: "mIDFAData", type: "string" },
  { tag: 16, field: "stReportInfo", type: "struct" },
  { tag: 17, field: "bUnbindDeviceId", type: "bool" },
  { tag: 18, field: "iRoleZoneId", type: "int" },
  { tag: 19, field: "stDidReqParam", type: "struct" },
  { tag: 20, field: "sDeviceId", type: "string" },
  { tag: 21, field: "sThisLoginDeviceUniqueId", type: "string" },
  { tag: 22, field: "sThisLoginDevice", type: "string" },
  { tag: 23, field: "sThisLoginOSLanguage", type: "string" },
  { tag: 24, field: "iThisLanguageId", type: "int" },
  { tag: 25, field: "iSwitchVersion", type: "int" },
  { tag: 26, field: "sLoginAccToken", type: "string" },
  { tag: 27, field: "sMd5", type: "string" },
  { tag: 28, field: "iLoginId", type: "int" },
  { tag: 29, field: "iClientTransferSource", type: "int" },
  { tag: 30, field: "sAppUuid", type: "string" },
  { tag: 31, field: "sAppClickId", type: "string" },
  { tag: 32, field: "iMagic", type: "int" },
  { tag: 33, field: "mNetEaseVerify", type: "string" },
  { tag: 34, field: "bNetEaseVerifyPass", type: "bool" },
  { tag: 35, field: "sInitInfo", type: "string" },
  { tag: 36, field: "iSrcAppType", type: "int" },
  { tag: 37, field: "iDeviceLevel", type: "int" },
  { tag: 38, field: "bForceCreateAccount", type: "bool" },
];

/** Cari definisi field Cmd_Login_Auth_CS per nomor tag SDP. */
function csFieldDef(tag) {
  return CS_TAG_FIELDS.find((c) => c.tag === tag);
}

/**
 * Cmd_Login_Auth_CS: paket dari client (Cmd_Login_Auth_CS, opcode 0x70000101)
 * setelah diurai dari body SDP. Field yang tidak ada di body hanya diisi
 * default kosong, supaya pemanggilan dari field lain tetap aman.
 */
class Cmd_Login_Auth_CS {
  constructor() {
    this.sAccountName = "";
    this.sAuthKey = "";
    this.sClientVersion = "";
    this.sChannel = "";
    this.sOSLanguage = "";
    this.iOSType = 0;
    this.mMiscData = "";
    this.iLocalZoneId = 0;
    this.iRegionId = 0;
    this.sCountry = "";
    this.sUserIP = "";
    this.uiCreateAlt = 0;
    this.uiConfirmNotOverrideFromZing = 0;
    this.sUnityVersion = "";
    this.sDeviceInfo = "";
    this.bUnbindDeviceId = false;
    this.iRoleZoneId = 0;
    this.sDeviceId = "";
    this.sLoginAccToken = "";
    this.sMd5 = "";
    this.iLoginId = 0;
    this.iClientTransferSource = 0;
    this.sAppUuid = "";
    this.sAppClickId = "";
    this.iMagic = 0;
    this.bForceCreateAccount = false;
  }

  /**
   * Urai body SDP menjadi instance Cmd_Login_Auth_CS.
   * Body berbentuk root struct (tag 0) + StructEnd.
   */
  static fromSdpBody(body) {
    const cs = new Cmd_Login_Auth_CS();
    if (!body) return cs;
    let nodes;
    try {
      nodes = sdp.decode(body);
    } catch (_) {
      return cs;
    }
    const root = nodes[0];
    if (!root || root.type !== sdp.T.STRUCT) return cs;
    for (const f of root.fields) {
      const def = csFieldDef(f.tag);
      if (!def) continue;
      if (def.type === "string") {
        cs[def.field] = f.type === sdp.T.STRING ? f.raw.toString("utf8") : "";
      } else if (def.type === "int" || def.type === "bool") {
        cs[def.field] = f.type === sdp.T.INT || f.type === sdp.T.NEG ? Number(f.v) : 0;
      }
    }
    return cs;
  }
}

/**
 * Cmd_Login_Auth_SC: paket response untuk Cmd_Login_Auth_CS.
 * Field dipilih dari akun (hasil lookup database/toko auth) supaya respons
 * menyesuaikan auth client yang sebenarnya.
 */
class Cmd_Login_Auth_SC {
  constructor(account = DEFAULT_LOGIN_AUTH_ACCOUNT) {
    this.iAccountId = account.iAccountId ?? 1n;
    this.sSessionKey = account.sSessionKey ?? "fs3c9d921a6cfd44c62259f88f";
    this.stZone = account.stZone || {
      iZoneId: 1,
      sZoneName: "petwirkepo",
      iStatus: 1,
      iFlag: 0,
    };
    this.vAccountInfo = account.vAccountInfo || [];
    this.sUserIP = account.sUserIP || "";
    this.sAccountName = account.sAccountName || "";
    this.sCountry = account.sCountry || "";
    this.iServerTimeMS = account.iServerTimeMS ?? BigInt(Date.now());
    this.bLocalZoneHasMerged = !!account.bLocalZoneHasMerged;
    this.bNewAccount =
      account.bNewAccount !== undefined ? !!account.bNewAccount : true;
    this.iAccountFlag = account.iAccountFlag ?? 2;
    this.uiCreateAlt = account.uiCreateAlt ?? 0;
    this.sIsp = account.sIsp || "";
    this.iAccCreateTime = account.iAccCreateTime ?? 1793530475;
    this.vSimpleRoleInfo = account.vSimpleRoleInfo || [];
    this.iTimeGmtOff = account.iTimeGmtOff ?? 0n;
  }

  /** Bungkus field akun menjadi body SDP untuk Cmd_Login_Auth_SC. */
  toSdpBody() {
    const sdpParts = [];
    sdpParts.push(Buffer.from([0x70])); // StructBegin

    // Tag 0: iAccountId (UInt64 -> BigInt)
    sdpParts.push(packInt(0, this.iAccountId));

    // Tag 1: sSessionKey
    sdpParts.push(packString(1, this.sSessionKey));

    // Tag 2: stZone (CmdZoneInfo struct)
    sdpParts.push(
      Buffer.concat([
        Buffer.from([0x72]), // StructBegin dengan Tag 2 (0x70 | 2)
        packInt(0, this.stZone.iZoneId),
        packString(1, this.stZone.sZoneName),
        packInt(2, this.stZone.iStatus),
        Buffer.from([0x80]), // StructEnd
      ]),
    );

    // Tag 3: vAccountInfo (List kosong)
    sdpParts.push(Buffer.from([0x53, 0x00]));

    // Tag 10: iServerTimeMS (UInt64 -> BigInt)
    sdpParts.push(packInt(10, this.iServerTimeMS));

    // Tag 11 - 14
    sdpParts.push(packInt(11, this.bLocalZoneHasMerged ? 1 : 0)); // bLocalZoneHasMerged
    sdpParts.push(packInt(12, this.bNewAccount ? 1 : 0)); // bNewAccount
    sdpParts.push(packInt(13, this.iAccountFlag)); // iAccountFlag
    sdpParts.push(packInt(14, this.uiCreateAlt)); // uiCreateAlt

    // Tag 19: iAccCreateTime
    sdpParts.push(packInt(19, this.iAccCreateTime));

    // --- TAG 20: vSimpleRoleInfo (List) ---
    const tag20Header = writeTag(20, 5); // Type 5 = List
    sdpParts.push(
      Buffer.concat([
        tag20Header,
        Buffer.from([0x01]), // Jumlah item di dalam list
      ]),
    );

    sdpParts.push(Buffer.from([0x80, 0x80])); // StructEnd utama
    return Buffer.concat(sdpParts);
  }
}

/**
 * Akun auth default (legacy) supaya perilaku lama tetap terjaga bila belum
 * ada akun yang cocok dengan informasi dari Cmd_Login_Auth_CS.
 */
const DEFAULT_LOGIN_AUTH_ACCOUNT = {
  iAccountId: 1n,
  sSessionKey: "fs3c9d921a6cfd44c62259f88f",
  stZone: { iZoneId: 1, sZoneName: "petwirkepo", iStatus: 1, iFlag: 0 },
  vAccountInfo: [],
  sUserIP: "",
  sAccountName: "",
  sCountry: "",
  bLocalZoneHasMerged: false,
  bNewAccount: true,
  iAccountFlag: 2,
  uiCreateAlt: 0,
  sIsp: "",
  iAccCreateTime: 1793530475,
  vSimpleRoleInfo: [],
  iTimeGmtOff: 0n,
};

/**
 * Database relasional untuk akun auth (SQLite via built-in `node:sqlite`,
 * tanpa dependensi npm baru). File: state/auth.db (diremote git, bukan bagian repo).
 * Setiap akun baru otomatis mendapat iAccountId berbeda (AUTOINCREMENT).
 */
const AUTH_DB_PATH = path.join(__dirname, "state", "auth.db");
const AUTH_DB = new DatabaseSync(AUTH_DB_PATH);
AUTH_DB.exec(`CREATE TABLE IF NOT EXISTS auth_accounts (
  i_account_id INTEGER PRIMARY KEY AUTOINCREMENT,
  s_account_name TEXT NOT NULL UNIQUE,
  s_auth_key TEXT NOT NULL DEFAULT '',
  s_session_key TEXT NOT NULL,
  st_zone_id INTEGER,
  st_zone_name TEXT,
  st_zone_status INTEGER,
  st_zone_flag INTEGER,
  s_country TEXT NOT NULL DEFAULT '',
  s_user_ip TEXT NOT NULL DEFAULT '',
  i_acc_create_time INTEGER NOT NULL,
  b_new_account INTEGER NOT NULL,
  i_account_flag INTEGER NOT NULL,
  ui_create_alt INTEGER NOT NULL,
  i_server_time_ms INTEGER NOT NULL
);`);
AUTH_DB.exec(
  "CREATE INDEX IF NOT EXISTS idx_auth_accounts_auth_key ON auth_accounts (LOWER(s_auth_key));",
);

/** Ubah baris database (snake_case) menjadi objek akun (camelCase). */
function authAccountFromRow(row) {
  return {
    iAccountId: BigInt(row.i_account_id),
    sAccountName: row.s_account_name || "",
    sAuthKey: row.s_auth_key || "",
    sSessionKey: row.s_session_key,
    stZone: {
      iZoneId: row.st_zone_id ?? 1,
      sZoneName: row.st_zone_name || "",
      iStatus: row.st_zone_status ?? 1,
      iFlag: row.st_zone_flag ?? 0,
    },
    sCountry: row.s_country || "",
    sUserIP: row.s_user_ip || "",
    iAccCreateTime: row.i_acc_create_time ?? 0,
    bNewAccount: !!row.b_new_account,
    iAccountFlag: row.i_account_flag ?? 2,
    uiCreateAlt: row.ui_create_alt ?? 0,
    iServerTimeMS: row.i_server_time_ms ? BigInt(row.i_server_time_ms) : BigInt(Date.now()),
  };
}

/** Daftarkan akun baru ke database auth. */
function registerAuthAccount(account) {
  AUTH_DB.prepare(
    `INSERT INTO auth_accounts (s_account_name, s_auth_key, s_session_key, st_zone_id, st_zone_name, st_zone_status, st_zone_flag, s_country, s_user_ip, i_acc_create_time, b_new_account, i_account_flag, ui_create_alt, i_server_time_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    account.sAccountName || "",
    account.sAuthKey || "",
    account.sSessionKey || "",
    account.stZone ? account.stZone.iZoneId ?? 1 : 1,
    account.stZone ? account.stZone.sZoneName || "" : "",
    account.stZone ? account.stZone.iStatus ?? 1 : 1,
    account.stZone ? account.stZone.iFlag ?? 0 : 0,
    account.sCountry || "",
    account.sUserIP || "",
    account.iAccCreateTime ?? 0,
    account.bNewAccount ? 1 : 0,
    account.iAccountFlag ?? 2,
    account.uiCreateAlt ?? 0,
    account.iServerTimeMS ? Number(account.iServerTimeMS) : Number(Date.now()),
  );
}

/** Cari akun dari informasi Cmd_Login_Auth_CS (nama akun -> auth key) di database. */
function findAuthAccount(cs) {
  const name = (cs.sAccountName || "").trim().toLowerCase();
  if (name) {
    const row = AUTH_DB.prepare(
      "SELECT * FROM auth_accounts WHERE LOWER(s_account_name) = ? LIMIT 1",
    ).get(name);
    if (row) return authAccountFromRow(row);
  }
  const authKey = (cs.sAuthKey || "").trim().toLowerCase();
  if (authKey) {
    const row = AUTH_DB.prepare(
      "SELECT * FROM auth_accounts WHERE LOWER(s_auth_key) = ? LIMIT 1",
    ).get(authKey);
    if (row) return authAccountFromRow(row);
  }
  return null;
}

/** Buat akun baru dari Cmd_Login_Auth_CS (akun yang belum ada di database). */
function createAuthAccount(cs) {
  const accountName = cs.sAccountName || "";
  if (!accountName) return DEFAULT_LOGIN_AUTH_ACCOUNT;
  const info = AUTH_DB.prepare(
    `INSERT INTO auth_accounts (s_account_name, s_auth_key, s_session_key, st_zone_id, st_zone_name, st_zone_status, st_zone_flag, s_country, s_user_ip, i_acc_create_time, b_new_account, i_account_flag, ui_create_alt, i_server_time_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    accountName,
    cs.sAuthKey || "",
    crypto.randomBytes(32).toString("base64"),
    cs.iLocalZoneId || 1,
    cs.sChannel || `zone-${cs.iLocalZoneId || 1}`,
    1,
    0,
    cs.sCountry || "",
    cs.sUserIP || "",
    Math.floor(Date.now() / 1000),
    1,
    2,
    cs.uiCreateAlt || 0,
    Date.now(),
  );
  const row = AUTH_DB.prepare("SELECT * FROM auth_accounts WHERE i_account_id = ?").get(info.lastInsertRowid);
  return authAccountFromRow(row);
}

/**
 * Build Cmd_Login_Auth_SC (opcode 0x70000201) untuk seq tertentu.
 * Akun dipakai bila tersedia (hasil lookup database/toko auth), supaya field
 * auth (iAccountId, sSessionKey, stZone, flag akun) sesuai akun yang login.
 */
function buildLoginAuthSC(seq, account = DEFAULT_LOGIN_AUTH_ACCOUNT) {
  const sc = new Cmd_Login_Auth_SC(account);
  const sdpBody = sc.toSdpBody();
  return packPacket(0x70000201, seq, sdpBody);
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
  Cmd_Login_Auth_CS,
  Cmd_Login_Auth_SC,
  findAuthAccount,
  createAuthAccount,
  registerAuthAccount,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  buildNetConnectSC,
  packPacket,
};

if (require.main === module) {
  startAuthServer().then(() => startZoneServer());
}

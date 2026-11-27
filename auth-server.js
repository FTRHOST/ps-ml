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
const ZONE_PORT = 30103;
const HOST = "0.0.0.0";
const SERVER_IP = process.env.SERVER_IP || "0.0.0.0";

/**
 *Override iAccountId (tag 0) di Cmd_Login_Auth_SC. Klien memakai field ini
 * untuk mengisi SystemData.m_uiID; tanpa nilai valid, Preparation diblokir.
 * Set AUTH_UID kosong untuk memakai id akun dari database.
 */
const AUTH_UID =
  process.env.AUTH_UID !== undefined && process.env.AUTH_UID !== ""
    ? BigInt(process.env.AUTH_UID)
    : null;

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

/** Emit list SDP; elemen ditulis dengan header bertag 0. */
function emitList(sdpParts, listTag, items, emitter) {
  if (!items || items.length === 0) {
    sdpParts.push(writeTag(listTag, 5), Buffer.from([0x00]));
    return;
  }
  sdpParts.push(writeTag(listTag, 5), writeVarUint(items.length));
  for (const item of items) emitter(sdpParts, item);
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
 * Peta field Cmd_Login_GetZone_CS -> nomor tag SDP.
 * Field pertama di dump.cs (iAccountId, offset 0x10) memakai tag 0 dan
 * nomor tag naik satu per field declaration. Tipe: 4 = string, 0 = int.
 */
const GETZONE_CS_TAG_FIELDS = [
  { tag: 0, field: "iAccountId", type: "int", bigint: true },
  { tag: 1, field: "sSessionKey", type: "string" },
  { tag: 2, field: "sClientVersion", type: "string" },
  { tag: 3, field: "sChannel", type: "string" },
  { tag: 4, field: "iRegionId", type: "int" },
  { tag: 5, field: "iGetType", type: "int" },
];

/** Cari definisi field Cmd_Login_GetZone_CS per nomor tag SDP. */
function getZoneCsFieldDef(tag) {
  return GETZONE_CS_TAG_FIELDS.find((c) => c.tag === tag);
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
        cs[def.field] =
          f.type === sdp.T.INT || f.type === sdp.T.NEG ? Number(f.v) : 0;
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

    // Tag 0: iAccountId (UInt64 -> BigInt). AUTH_UID menimpa id DB bila
    // di-set, supaya identitas klien sama dengan uid role yang dipakai replay.
    sdpParts.push(packInt(0, AUTH_UID !== null ? AUTH_UID : this.iAccountId));

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
 * Cmd_Login_GetZone_CS: paket dari client (Cmd_Login_GetZone_CS, opcode 0x70000301)
 * setelah diurai dari body SDP. Field yang tidak ada di body hanya diisi
 * default kosong, supaya pemanggilan dari field lain tetap aman.
 */
class Cmd_Login_GetZone_CS {
  constructor() {
    this.iAccountId = 0n;
    this.sSessionKey = "";
    this.sClientVersion = "";
    this.sChannel = "";
    this.iRegionId = 0;
    this.iGetType = 0;
  }

  /**
   * Urai body SDP menjadi instance Cmd_Login_GetZone_CS.
   * Body berbentuk root struct (tag 0) + StructEnd.
   */
  static fromSdpBody(body) {
    const cs = new Cmd_Login_GetZone_CS();
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
      const def = getZoneCsFieldDef(f.tag);
      if (!def) continue;
      if (def.type === "string") {
        cs[def.field] = f.type === sdp.T.STRING ? f.raw.toString("utf8") : "";
      } else if (def.type === "int" || def.type === "bool") {
        if (def.bigint) {
          cs[def.field] =
            f.type === sdp.T.INT || f.type === sdp.T.NEG ? BigInt(f.v) : 0n;
        } else {
          cs[def.field] =
            f.type === sdp.T.INT || f.type === sdp.T.NEG ? Number(f.v) : 0;
        }
      }
    }
    return cs;
  }
}

/**
 * Cmd_Login_GetZone_SC: paket response untuk Cmd_Login_GetZone_CS.
 * Membawa daftar zone (vZoneList) dan role (vRoleList) untuk akun yang login.
 */
class Cmd_Login_GetZone_SC {
  constructor(account = DEFAULT_LOGIN_AUTH_ACCOUNT) {
    const zone =
      (account && account.stZone) || DEFAULT_LOGIN_AUTH_ACCOUNT.stZone;
    this.vZoneList = [
      {
        iZoneId: zone.iZoneId ?? 1,
        sZoneName: zone.sZoneName || "",
        iStatus: zone.iStatus ?? 1,
        iFlag: zone.iFlag ?? 0,
      },
    ];
    // Tanpa entri ini klien menganggap akun belum punya role dan membuka UI
    // Create Character meskipun Cmd_Role_Init_SC sudah dikirim dari replay.
    this.vRoleList = [
      {
        iZoneID: zone.iZoneId ?? 1,
        iCreateRoleTime: 1543443539,
        iAreaTag: 14,
        bChangeName: 0,
        iCreateRoleAreaTag: 14,
        iLevel: Number(process.env.LEVEL || 28),
        iForceChangeAreaTagReason: 0,
        sCreateRoleCountry: "ID",
        vABTestExpParam: [],
      },
    ];
    this.iRegionId = account ? (account.iRegionId ?? 0) : 0;
  }

  /** Bungkus field akun menjadi body SDP untuk Cmd_Login_GetZone_SC. */
  toSdpBody() {
    const zone = this.vZoneList[0] || {};
    const sdpParts = [];
    sdpParts.push(Buffer.from([0x70])); // StructBegin

    // Tag 0: vZoneList (List of CmdZoneInfo) -> 1 item
    sdpParts.push(Buffer.from([0x50, 0x01])); // Type 5 (List) tag 0, jumlah item 1
    sdpParts.push(Buffer.from([0x70])); // StructBegin item (tag 0)
    sdpParts.push(packInt(0, BigInt(zone.iZoneId ?? 1)));
    sdpParts.push(packString(1, zone.sZoneName || ""));
    sdpParts.push(packInt(2, BigInt(zone.iStatus ?? 1)));
    sdpParts.push(packInt(3, BigInt(zone.iFlag ?? 0)));
    sdpParts.push(Buffer.from([0x80])); // StructEnd item

    // Tag 1: vRoleList (List of SimpleRoleInfo)
    sdpParts.push(Buffer.from([0x51, this.vRoleList.length & 0xff]));
    for (const role of this.vRoleList) {
      sdpParts.push(
        Buffer.concat([
          Buffer.from([0x70]), // StructBegin item (tag 0)
          packInt(0, BigInt(role.iZoneID ?? 1)),
          packInt(1, BigInt(role.iCreateRoleTime ?? 0)),
          packInt(2, BigInt(role.iAreaTag ?? 0)),
          packInt(3, BigInt(role.bChangeName ? 1 : 0)),
          packInt(4, BigInt(role.iCreateRoleAreaTag ?? 0)),
          packInt(5, BigInt(role.iLevel ?? 1)),
          packInt(6, BigInt(role.iForceChangeAreaTagReason ?? 0)),
          packString(7, role.sCreateRoleCountry || ""),
          Buffer.from([0x50, (role.vABTestExpParam || []).length & 0xff]),
          ...(role.vABTestExpParam || []).map((s) => packString(0, s)),
          Buffer.from([0x80]), // StructEnd item
        ]),
      );
    }

    // Tag 2: iRegionId
    sdpParts.push(packInt(2, BigInt(this.iRegionId || 0)));

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
 * Database relasional server (SQLite via built-in `node:sqlite`, tanpa
 * dependensi npm baru). Menyimpan akun, field role, kepemilikan hero/skin, dan
 * state server. File: state/game.db (diremote git, bukan bagian repo).
 * Setiap akun baru otomatis mendapat iAccountId berbeda (AUTOINCREMENT).
 */
const AUTH_DB_PATH = path.join(__dirname, "state", "game.db");
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
  i_region_id INTEGER NOT NULL DEFAULT 0,
  i_acc_create_time INTEGER NOT NULL,
  b_new_account INTEGER NOT NULL,
  i_account_flag INTEGER NOT NULL,
  ui_create_alt INTEGER NOT NULL,
  i_server_time_ms INTEGER NOT NULL
);`);
AUTH_DB.exec(
  "CREATE INDEX IF NOT EXISTS idx_auth_accounts_auth_key ON auth_accounts (LOWER(s_auth_key));",
);

/**
 * State ringan yang tetap ada setelah server restart. Dipakai supaya request
 * zone dari klien yang sudah terhubung (tanpa login ulang) tetap dibinding ke
 * akun yang terakhir login, bukan jatuh ke id 1.
 */
AUTH_DB.exec(
  "CREATE TABLE IF NOT EXISTS server_state (s_key TEXT PRIMARY KEY, s_value TEXT NOT NULL);",
);
function getServerState(key) {
  const row = AUTH_DB.prepare(
    "SELECT s_value FROM server_state WHERE s_key = ?",
  ).get(String(key));
  return row ? row.s_value : null;
}
function setServerState(key, value) {
  AUTH_DB.prepare(
    `INSERT INTO server_state (s_key, s_value) VALUES (?, ?)
     ON CONFLICT(s_key) DO UPDATE SET s_value = excluded.s_value`,
  ).run(String(key), String(value));
}
function getLastAccountId() {
  const id = Number(getServerState("last_account_id"));
  return Number.isFinite(id) && id > 0 ? id : null;
}
function setLastAccountId(accountId) {
  setServerState("last_account_id", String(accountId));
}

// Migrasi ringan: pastikan kolom i_region_id ada pada database lama.
{
  const cols = AUTH_DB.prepare("PRAGMA table_info(auth_accounts)").all();
  if (!cols.some((c) => c.name === "i_region_id")) {
    AUTH_DB.exec(
      "ALTER TABLE auth_accounts ADD COLUMN i_region_id INTEGER NOT NULL DEFAULT 0;",
    );
  }
}

/**
 * Field utama Cmd_Role_Init_SC yang berasal dari capture asli (tag 0..23).
 * `iUid` selalu mengikuti i_account_id (primary key tabel), `sName` default
 * `Petwir_<nomor player>` berdasarkan urutan i_account_id di auth_accounts.
 * Tag lain memakai nilai capture; sisanya (termasuk blob tag 26) tidak diubah.
 */
const ROLE_INIT_FIELDS = Object.freeze([
  { name: "iUid", tag: 0, column: "i_uid", type: "int", default: null },
  { name: "sName", tag: 1, column: "s_name", type: "string", default: null },
  { name: "iExp", tag: 2, column: "i_exp", type: "int", default: 27446 },
  { name: "iLevel", tag: 3, column: "i_level", type: "int", default: 89 },
  { name: "iCoin", tag: 4, column: "i_coin", type: "int", default: 65877 },
  { name: "iGuideStep", tag: 5, column: "i_guide_step", type: "int", default: 8 },
  { name: "iFaceId", tag: 7, column: "i_face_id", type: "int", default: 101 },
  { name: "iNationality", tag: 8, column: "i_nationality", type: "int", default: 14 },
  { name: "iRoleFlag", tag: 10, column: "i_role_flag", type: "int", default: 1978 },
  { name: "iDiamond", tag: 11, column: "i_diamond", type: "int", default: 100000 },
  { name: "iCreateRoleTime", tag: 12, column: "i_create_role_time", type: "int", default: 1543443539 },
  { name: "iLastLoginTime", tag: 13, column: "i_last_login_time", type: "int", default: 1795723886 },
  { name: "iRankLevel", tag: 15, column: "i_rank_level", type: "int", default: 114 },
  { name: "iGuideSwitchFlag", tag: 16, column: "i_guide_switch_flag", type: "int", default: 4294967295 },
  { name: "iPVPRank", tag: 17, column: "i_pvp_rank", type: "int", default: 2855 },
  { name: "iRankSeasonGMIsOpen", tag: 18, column: "i_rank_season_gm_is_open", type: "int", default: 1 },
  { name: "iFaceBorderId", tag: 19, column: "i_face_border_id", type: "int", default: 127 },
  { name: "iTotalCharge", tag: 20, column: "i_total_charge", type: "int", default: 298 },
  { name: "iPreviousFaceUploadTime", tag: 23, column: "i_previous_face_upload_time", type: "int", default: 1735306048 },
]);

function roleInitSqlType(def) {
  return def.type === "string" ? "TEXT" : "INTEGER";
}

AUTH_DB.exec(
  `CREATE TABLE IF NOT EXISTS role_init_fields (
  i_account_id INTEGER PRIMARY KEY,
  ${ROLE_INIT_FIELDS.map(
    (def) =>
      `${def.column} ${roleInitSqlType(def)} NOT NULL` +
      (def.default === null ? "" : ` DEFAULT ${def.default}`),
  ).join(",\n  ")}
);`,
);

// Migrasi ringan untuk database yang sudah punya tabel dengan kolom lebih lama.
{
  const cols = AUTH_DB.prepare("PRAGMA table_info(role_init_fields)").all();
  for (const def of ROLE_INIT_FIELDS) {
    if (cols.some((c) => c.name === def.column)) continue;
    const fallback = def.default === null ? (def.type === "string" ? "''" : "0") : def.default;
    AUTH_DB.exec(
      `ALTER TABLE role_init_fields ADD COLUMN ${def.column} ${roleInitSqlType(def)} NOT NULL DEFAULT ${fallback};`,
    );
  }
}

/** Nama default berdasarkan urutan akun (i_account_id ascending). */
function roleInitNameForAccount(accountId) {
  const row = AUTH_DB.prepare(
    "SELECT COUNT(*) AS player_no FROM auth_accounts WHERE i_account_id <= ?",
  ).get(Number(accountId));
  return `Petwir_${Number(row && row.player_no ? row.player_no : 1)}`;
}

/** Pastikan satu baris role_init_fields ada; kembalikan override untuk patcher. */
function ensureRoleInitFields(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return null;
  AUTH_DB.prepare(
    "INSERT OR IGNORE INTO role_init_fields (i_account_id, i_uid, s_name) VALUES (?, ?, ?)",
  ).run(id, id, roleInitNameForAccount(id));
  // iUid wajib mengikuti primary key meski baris sudah ada.
  AUTH_DB.prepare("UPDATE role_init_fields SET i_uid = ? WHERE i_account_id = ?").run(id, id);
  const row = AUTH_DB.prepare(
    "SELECT * FROM role_init_fields WHERE i_account_id = ?",
  ).get(id);
  if (!row) return null;
  const values = {};
  for (const def of ROLE_INIT_FIELDS) {
    const raw = row[def.column];
    if (raw === null || raw === undefined) continue;
    values[def.tag] =
      def.type === "string" ? String(raw) : BigInt(raw);
  }
  const playerNo = Number(String(row.s_name || "").replace(/^Petwir_/, ""));
  return { accountId: id, playerNo: Number.isFinite(playerNo) ? playerNo : 1, values };
}

/** Isi baris untuk semua akun yang sudah ada (nomor player sesuai urutan id). */
function seedRoleInitFieldsForAllAccounts() {
  const rows = AUTH_DB.prepare(
    "SELECT i_account_id FROM auth_accounts ORDER BY i_account_id ASC",
  ).all();
  rows.forEach((row, index) => {
    const id = Number(row.i_account_id);
    AUTH_DB.prepare(
      "INSERT OR IGNORE INTO role_init_fields (i_account_id, i_uid, s_name) VALUES (?, ?, ?)",
    ).run(id, id, `Petwir_${index + 1}`);
    AUTH_DB.prepare("UPDATE role_init_fields SET i_uid = ? WHERE i_account_id = ?").run(id, id);
  });
}
seedRoleInitFieldsForAllAccounts();

/**
 * CmdHeroData (dump.cs): satu baris per hero yang dimiliki sebuah akun.
 * `iHeroId` adalah kunci bersama i_account_id. Field lain default 0 yang
 * berarti "belum diset" (tidak dikirim ke klien).
 */
const HERO_DATA_FIELDS = Object.freeze([
  { name: "iHeroId", tag: 0, column: "i_hero_id", default: null },
  { name: "iCurrentSkin", tag: 1, column: "i_current_skin", default: 0 },
  { name: "iLimitTime", tag: 2, column: "i_limit_time", default: 0 },
  { name: "iSkinSource", tag: 3, column: "i_skin_source", default: 0 },
  { name: "iCurrentStatue", tag: 4, column: "i_current_statue", default: 0 },
  { name: "iStatueSource", tag: 5, column: "i_statue_source", default: 0 },
  { name: "iFightPowerLvl", tag: 6, column: "i_fight_power_lvl", default: 0 },
  { name: "iFightPowerValue", tag: 7, column: "i_fight_power_value", default: 0 },
]);
const HERO_DATA_COLUMNS = HERO_DATA_FIELDS.map((d) => d.column).join(", ");
const HERO_DATA_PLACEHOLDERS = HERO_DATA_FIELDS.map(() => "?").join(", ");
const HERO_DATA_UPDATE_SET = HERO_DATA_FIELDS.slice(1)
  .map((d) => `${d.column} = excluded.${d.column}`)
  .join(", ");

function heroDataColumnSql(def) {
  return (
    `${def.column} INTEGER NOT NULL` +
    (def.default === null ? "" : ` DEFAULT ${def.default}`)
  );
}

for (const table of ["cmd_hero_data", "hero_get_list"]) {
  AUTH_DB.exec(
    `CREATE TABLE IF NOT EXISTS ${table} (
  i_account_id INTEGER NOT NULL,
  ${HERO_DATA_FIELDS.map(heroDataColumnSql).join(",\n  ")},
  PRIMARY KEY (i_account_id, i_hero_id)
);`,
  );
  const cols = AUTH_DB.prepare(`PRAGMA table_info(${table})`).all();
  for (const def of HERO_DATA_FIELDS) {
    if (cols.some((c) => c.name === def.column)) continue;
    AUTH_DB.exec(
      `ALTER TABLE ${table} ADD COLUMN ${def.column} INTEGER NOT NULL DEFAULT ${def.default === null ? 0 : def.default};`,
    );
  }
}

/** Baris DB -> objek CmdHeroData (nama field dump.cs). */
function heroDataFromRow(row) {
  const out = { iHeroId: Number(row.i_hero_id) };
  for (const def of HERO_DATA_FIELDS.slice(1)) {
    out[def.name] = Number(row[def.column] || 0);
  }
  return out;
}

/** Ambil semua CmdHeroData milik akun (tabel sumber). */
function getCmdHeroData(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  return AUTH_DB.prepare(
    `SELECT * FROM cmd_hero_data WHERE i_account_id = ? ORDER BY i_hero_id ASC`,
  )
    .all(id)
    .map(heroDataFromRow);
}

/** Ambil hasil GetList (tabel turunan dari cmd_hero_data). */
function getHeroGetList(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  return AUTH_DB.prepare(
    `SELECT * FROM hero_get_list WHERE i_account_id = ? ORDER BY i_hero_id ASC`,
  )
    .all(id)
    .map(heroDataFromRow);
}

/** Simpan/perbarui CmdHeroData per akun + hero. Field yang tidak diberi = 0. */
function upsertCmdHeroData(accountId, rows) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0 || !Array.isArray(rows)) return 0;
  const stmt = AUTH_DB.prepare(
    `INSERT INTO cmd_hero_data (i_account_id, ${HERO_DATA_COLUMNS})
     VALUES (?, ${HERO_DATA_PLACEHOLDERS})
     ON CONFLICT(i_account_id, i_hero_id) DO UPDATE SET ${HERO_DATA_UPDATE_SET}`,
  );
  let count = 0;
  for (const input of rows) {
    const heroId = Number(
      input.iHeroId !== undefined ? input.iHeroId : input[0],
    );
    if (!Number.isInteger(heroId) || heroId <= 0) continue;
    const values = HERO_DATA_FIELDS.map((def) => {
      const raw =
        input[def.name] !== undefined
          ? input[def.name]
          : input[def.tag] !== undefined
            ? input[def.tag]
            : def.default ?? 0;
      return Number(raw) || 0;
    });
    stmt.run(id, ...values);
    count++;
  }
  return count;
}

/** Bangun ulang tabel hero_get_list dari cmd_hero_data untuk satu akun. */
function refreshHeroGetList(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  AUTH_DB.prepare("DELETE FROM hero_get_list WHERE i_account_id = ?").run(id);
  AUTH_DB.prepare(
    `INSERT INTO hero_get_list (i_account_id, ${HERO_DATA_COLUMNS})
     SELECT ?, ${HERO_DATA_COLUMNS} FROM cmd_hero_data
     WHERE i_account_id = ? ORDER BY i_hero_id ASC`,
  ).run(id, id);
  return getHeroGetList(id);
}

/** Hero default untuk setiap akun: 1 sampai 135, semua field = 0 (belum diset). */
const DEFAULT_OWNED_HEROES = Object.freeze(
  Array.from({ length: 135 }, (_, i) => ({ iHeroId: i + 1 })),
);

/**
 * Pastikan akun memiliki seluruh hero default. Baris yang sudah ada tidak
 * ditimpa supaya perubahan skin hasil "Use" tidak hilang.
 */
function ensureHeroDataForAccount(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  const existingIds = new Set(getCmdHeroData(id).map((r) => r.iHeroId));
  const missing = DEFAULT_OWNED_HEROES.filter(
    (row) => !existingIds.has(row.iHeroId),
  );
  if (missing.length) upsertCmdHeroData(id, missing);
  return refreshHeroGetList(id);
}

/** Update skin yang sedang dipakai, disimpan ke tabel sumber + GetList. */
function setHeroCurrentSkin(accountId, heroId, skinId) {
  const id = Number(accountId);
  const hero = Number(heroId);
  const skin = Number(skinId);
  if (!Number.isFinite(id) || id <= 0 || !Number.isInteger(hero) || hero <= 0) {
    return [];
  }
  const existing =
    getCmdHeroData(id).find((r) => r.iHeroId === hero) || { iHeroId: hero };
  upsertCmdHeroData(id, [{ ...existing, iCurrentSkin: skin || 0 }]);
  // Skin yang dipakai otomatis menjadi milik akun, supaya vSkinList selalu
  // memuat skin yang sedang dipakai hero.
  if (skin > 0 && !getCmdHeroSkin(id).some((r) => r.iId === skin)) {
    upsertCmdHeroSkin(id, [{ iId: skin, iSource: 1 }]);
    refreshSkinGetList(id);
  }
  return refreshHeroGetList(id);
}

/**
 * CmdHeroSkin (dump.cs): satu baris per skin yang dimiliki akun.
 * Tag SDP mengikuti urutan field: 0=iId, 1=iLimitTime, 2=iSource,
 * 3=iLimitTimeMagicChess, 4=iGetTime, 5=vDragonCrystalId,
 * 6=uiCurDragonCrystalId, 7=bSmartMagicUnlock, 8=iButtonSkin.
 */
const HERO_SKIN_FIELDS = Object.freeze([
  { name: "iId", tag: 0, column: "i_id", type: "int", default: null },
  { name: "iLimitTime", tag: 1, column: "i_limit_time", type: "int", default: 0 },
  { name: "iSource", tag: 2, column: "i_source", type: "int", default: 0 },
  { name: "iLimitTimeMagicChess", tag: 3, column: "i_limit_time_magic_chess", type: "int", default: 0 },
  { name: "iGetTime", tag: 4, column: "i_get_time", type: "int", default: 0 },
  { name: "vDragonCrystalId", tag: 5, column: "v_dragon_crystal_id", type: "json", default: "[]" },
  { name: "uiCurDragonCrystalId", tag: 6, column: "ui_cur_dragon_crystal_id", type: "int", default: 0 },
  { name: "bSmartMagicUnlock", tag: 7, column: "b_smart_magic_unlock", type: "int", default: 0 },
  { name: "iButtonSkin", tag: 8, column: "i_button_skin", type: "int", default: 0 },
]);
const HERO_SKIN_COLUMNS = HERO_SKIN_FIELDS.map((d) => d.column).join(", ");
const HERO_SKIN_PLACEHOLDERS = HERO_SKIN_FIELDS.map(() => "?").join(", ");
const HERO_SKIN_UPDATE_SET = HERO_SKIN_FIELDS.slice(1)
  .map((d) => `${d.column} = excluded.${d.column}`)
  .join(", ");

function heroSkinSqlType(def) {
  return def.type === "json" ? "TEXT" : "INTEGER";
}

/** Default SQL: angka apa adanya, string JSON dikutip dengan aman. */
function heroSkinDefaultSql(def) {
  const value = def.default === null ? 0 : def.default;
  return typeof value === "number"
    ? String(value)
    : `'${String(value).replace(/'/g, "''")}'`;
}

for (const table of ["cmd_hero_skin", "skin_get_list"]) {
  AUTH_DB.exec(
    `CREATE TABLE IF NOT EXISTS ${table} (
  i_account_id INTEGER NOT NULL,
  ${HERO_SKIN_FIELDS.map(
    (d) =>
      `${d.column} ${heroSkinSqlType(d)} NOT NULL` +
      (d.default === null ? "" : ` DEFAULT ${heroSkinDefaultSql(d)}`),
  ).join(",\n  ")},
  PRIMARY KEY (i_account_id, i_id)
);`,
  );
  const cols = AUTH_DB.prepare(`PRAGMA table_info(${table})`).all();
  for (const def of HERO_SKIN_FIELDS) {
    if (cols.some((c) => c.name === def.column)) continue;
    AUTH_DB.exec(
      `ALTER TABLE ${table} ADD COLUMN ${def.column} ${heroSkinSqlType(def)} NOT NULL DEFAULT ${heroSkinDefaultSql(def)};`,
    );
  }
}

/** Baris DB -> objek CmdHeroSkin (nama field dump.cs). */
function heroSkinFromRow(row) {
  const out = { iId: Number(row.i_id) };
  for (const def of HERO_SKIN_FIELDS.slice(1)) {
    if (def.type === "json") {
      let arr = [];
      try {
        arr = JSON.parse(row[def.column] || "[]");
      } catch (_) {}
      out[def.name] = Array.isArray(arr) ? arr.map(Number) : [];
    } else {
      out[def.name] = Number(row[def.column] || 0);
    }
  }
  return out;
}

function getCmdHeroSkin(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  return AUTH_DB.prepare(
    `SELECT * FROM cmd_hero_skin WHERE i_account_id = ? ORDER BY i_id ASC`,
  )
    .all(id)
    .map(heroSkinFromRow);
}

/** Tabel hasil query skin, dipakai saat membangun vSkinList. */
function getSkinGetList(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  return AUTH_DB.prepare(
    `SELECT * FROM skin_get_list WHERE i_account_id = ? ORDER BY i_id ASC`,
  )
    .all(id)
    .map(heroSkinFromRow);
}

function upsertCmdHeroSkin(accountId, rows) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0 || !Array.isArray(rows)) return 0;
  const stmt = AUTH_DB.prepare(
    `INSERT INTO cmd_hero_skin (i_account_id, ${HERO_SKIN_COLUMNS})
     VALUES (?, ${HERO_SKIN_PLACEHOLDERS})
     ON CONFLICT(i_account_id, i_id) DO UPDATE SET ${HERO_SKIN_UPDATE_SET}`,
  );
  let count = 0;
  for (const input of rows) {
    const skinId = Number(input.iId !== undefined ? input.iId : input[0]);
    if (!Number.isInteger(skinId) || skinId <= 0) continue;
    const values = HERO_SKIN_FIELDS.map((def) => {
      const raw =
        input[def.name] !== undefined
          ? input[def.name]
          : input[def.tag] !== undefined
            ? input[def.tag]
            : def.default;
      if (def.type === "json") {
        return Array.isArray(raw) ? JSON.stringify(raw.map(Number)) : String(raw || "[]");
      }
      return Number(raw) || 0;
    });
    stmt.run(id, ...values);
    count++;
  }
  return count;
}

function refreshSkinGetList(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  AUTH_DB.prepare("DELETE FROM skin_get_list WHERE i_account_id = ?").run(id);
  AUTH_DB.prepare(
    `INSERT INTO skin_get_list (i_account_id, ${HERO_SKIN_COLUMNS})
     SELECT ?, ${HERO_SKIN_COLUMNS} FROM cmd_hero_skin
     WHERE i_account_id = ? ORDER BY i_id ASC`,
  ).run(id, id);
  return getSkinGetList(id);
}

/** Skin default untuk setiap akun: hanya 1189. */
const DEFAULT_OWNED_SKINS = Object.freeze([1189]);

function seedDefaultSkins(accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) return [];
  const existing = new Set(getCmdHeroSkin(id).map((r) => r.iId));
  const missing = DEFAULT_OWNED_SKINS.filter((skin) => !existing.has(skin)).map(
    (skin) => ({ iId: skin, iSource: 1 }),
  );
  if (missing.length) upsertCmdHeroSkin(id, missing);
  return refreshSkinGetList(id);
}

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
    iRegionId: row.i_region_id ?? 0,
    iAccCreateTime: row.i_acc_create_time ?? 0,
    bNewAccount: !!row.b_new_account,
    iAccountFlag: row.i_account_flag ?? 2,
    uiCreateAlt: row.ui_create_alt ?? 0,
    iServerTimeMS: row.i_server_time_ms
      ? BigInt(row.i_server_time_ms)
      : BigInt(Date.now()),
  };
}

/** Daftarkan akun baru ke database auth. */
function registerAuthAccount(account) {
  AUTH_DB.prepare(
    `INSERT INTO auth_accounts (s_account_name, s_auth_key, s_session_key, st_zone_id, st_zone_name, st_zone_status, st_zone_flag, s_country, s_user_ip, i_region_id, i_acc_create_time, b_new_account, i_account_flag, ui_create_alt, i_server_time_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    account.sAccountName || "",
    account.sAuthKey || "",
    account.sSessionKey || "",
    account.stZone ? (account.stZone.iZoneId ?? 1) : 1,
    account.stZone ? account.stZone.sZoneName || "" : "",
    account.stZone ? (account.stZone.iStatus ?? 1) : 1,
    account.stZone ? (account.stZone.iFlag ?? 0) : 0,
    account.sCountry || "",
    account.sUserIP || "",
    account.iRegionId ?? 0,
    account.iAccCreateTime ?? 0,
    account.bNewAccount ? 1 : 0,
    account.iAccountFlag ?? 2,
    account.uiCreateAlt ?? 0,
    account.iServerTimeMS ? Number(account.iServerTimeMS) : Number(Date.now()),
  );
  ensureRoleInitFields(Number(info.lastInsertRowid));
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

/**
 * Cari akun dari database auth berdasarkan i_account_id
 * (diambil dari Cmd_Login_GetZone_CS).
 */
function findAuthAccountById(id) {
  if (id === null || id === undefined || id === "") return null;
  let accountId;
  try {
    accountId = BigInt(id);
  } catch (_) {
    return null; // iAccountId tidak valid -> anggap tidak ada
  }
  const row = AUTH_DB.prepare(
    "SELECT * FROM auth_accounts WHERE i_account_id = ? LIMIT 1",
  ).get(accountId);
  if (!row) return null;
  return authAccountFromRow(row);
}

/** Buat akun baru dari Cmd_Login_Auth_CS (akun yang belum ada di database). */
function createAuthAccount(cs) {
  const accountName = cs.sAccountName || "";
  if (!accountName) return DEFAULT_LOGIN_AUTH_ACCOUNT;
  const info = AUTH_DB.prepare(
    `INSERT INTO auth_accounts (s_account_name, s_auth_key, s_session_key, st_zone_id, st_zone_name, st_zone_status, st_zone_flag, s_country, s_user_ip, i_region_id, i_acc_create_time, b_new_account, i_account_flag, ui_create_alt, i_server_time_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    cs.iRegionId || 0,
    Math.floor(Date.now() / 1000),
    1,
    2,
    cs.uiCreateAlt || 0,
    Date.now(),
  );
  const row = AUTH_DB.prepare(
    "SELECT * FROM auth_accounts WHERE i_account_id = ?",
  ).get(info.lastInsertRowid);
  ensureRoleInitFields(Number(info.lastInsertRowid));
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

/**
 * Build Cmd_Login_GetZone_SC (opcode 0x70000401) untuk seq tertentu.
 * Daftar zone diambil dari akun (hasil lookup database), sehingga client
 * langsung diarahkan ke zone yang tersimpan untuk akun tersebut.
 */
function buildLoginGetZoneSC(seq, account = DEFAULT_LOGIN_AUTH_ACCOUNT) {
  const sc = new Cmd_Login_GetZone_SC(account);
  const sdpBody = sc.toSdpBody();
  return packPacket(0x70000401, seq, sdpBody);
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
  sdpParts.push(packString(2, "2.2.30.1256.1"));

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

// ---------------------------------------------------------------------------
// Room (Cmd_Room_*)
// ---------------------------------------------------------------------------
/** Nilai default room; env menang supaya mode VS AI bisa dipilih tanpa edit kode. */
function roomDefaults() {
  return {
    pvpType: Number(
      process.env.ROOM_PVP_TYPE !== undefined ? process.env.ROOM_PVP_TYPE : 1,
    ),
    pvpMode: Number(process.env.ROOM_PVP_MODE || 0),
    mapId: Number(process.env.ROOM_MAP_ID || 1),
    zoneId: Number(process.env.ROOM_ZONE_ID || 9218),
    level: Number(process.env.ROOM_LEVEL || 3),
    faceId: Number(process.env.ROOM_FACE_ID || 101),
    nationality: Number(process.env.ROOM_NATIONALITY || 2),
  };
}

function withRoleProfile(defaults, profile) {
  const out = { ...defaults };
  if (!profile) return out;
  for (const [key, value] of Object.entries(profile)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

/** Emit RoomPlayerInfo (tag lihat visit() di dump.cs). */
function emitRoomPlayerInfo(sdpParts, player, structTag = 0) {
  if (!player) return;
  sdpParts.push(writeTag(structTag, 7)); // StructBegin
  sdpParts.push(packInt(0, BigInt(player.uid ?? 0)));
  if (player.svrId !== undefined) sdpParts.push(packInt(1, BigInt(player.svrId)));
  if (player.pos !== undefined) sdpParts.push(packInt(2, BigInt(player.pos)));
  if (player.name) sdpParts.push(packString(3, player.name));
  if (player.level !== undefined) sdpParts.push(packInt(4, BigInt(player.level)));
  if (player.faceId !== undefined) sdpParts.push(packInt(5, BigInt(player.faceId)));
  if (player.nationality !== undefined)
    sdpParts.push(packInt(6, BigInt(player.nationality)));
  if (player.rankLevel !== undefined)
    sdpParts.push(packInt(7, BigInt(player.rankLevel)));
  if (player.faceBorderId !== undefined)
    sdpParts.push(packInt(9, BigInt(player.faceBorderId)));
  if (player.isOnline) sdpParts.push(packInt(22, 1));
  if (player.isReady) sdpParts.push(packInt(23, 1));
  if (player.pvpType !== undefined) sdpParts.push(packInt(34, BigInt(player.pvpType)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Emit RoomInfo. Urutan wajib naik: 0,1,3 (players),4,6,7. */
function emitRoomInfo(sdpParts, info, structTag = 0) {
  if (!info) return;
  sdpParts.push(writeTag(structTag, 7)); // StructBegin
  sdpParts.push(packInt(0, BigInt(info.roomId ?? 0)));
  if (info.pvpType !== undefined) sdpParts.push(packInt(1, BigInt(info.pvpType)));
  emitList(sdpParts, 3, info.players || [], emitRoomPlayerInfo);
  if (info.matchVersion !== undefined)
    sdpParts.push(packInt(4, BigInt(info.matchVersion)));
  if (info.mapId !== undefined) sdpParts.push(packInt(6, BigInt(info.mapId)));
  if (info.pvpMode !== undefined) sdpParts.push(packInt(7, BigInt(info.pvpMode)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Body Cmd_Room_Enter_SC (0x7000c157 / 0x7000c357). */
function buildRoomEnterSCBody(opts = {}) {
  const d = withRoleProfile(roomDefaults(), opts.profile);
  const pvpType = opts.pvpType ?? d.pvpType;
  const roomId = opts.roomId ?? 2;
  const player = opts.player || {
    uid: d.uid ?? ROLE_UID_FALLBACK,
    svrId: d.zoneId,
    pos: 1,
    name: d.name || ROLE_NAME_FALLBACK,
    level: d.level,
    faceId: d.faceId,
    nationality: d.nationality,
    rankLevel: d.rankLevel,
    faceBorderId: d.faceBorderId,
    isOnline: true,
    isReady: true,
    pvpType,
  };
  const roomInfo = opts.roomInfo || {
    roomId,
    pvpType,
    matchVersion: opts.matchVersion ?? 100,
    mapId: opts.mapId ?? d.mapId,
    pvpMode: opts.pvpMode ?? d.pvpMode,
    players: [player],
  };
  const parts = [Buffer.from([0x70])];
  emitRoomPlayerInfo(parts, player, 1);
  emitRoomInfo(parts, roomInfo, 2);
  parts.push(packInt(3, 0)); // errorCode
  parts.push(packInt(12, BigInt(pvpType)));
  parts.push(Buffer.from([0x80, 0x80]));
  return Buffer.concat(parts);
}

/** Body Cmd_Room_GetInfo_SC (0x7000c957). */
function buildRoomGetInfoSCBody(opts = {}) {
  const d = withRoleProfile(roomDefaults(), opts.profile);
  const pvpType = opts.pvpType ?? d.pvpType;
  const roomId = opts.roomId ?? 2;
  const info = {
    roomId,
    pvpType,
    matchVersion: opts.matchVersion ?? 100,
    mapId: opts.mapId ?? d.mapId,
    pvpMode: opts.pvpMode ?? d.pvpMode,
    players: [
      {
        uid: d.uid ?? ROLE_UID_FALLBACK,
        svrId: d.zoneId,
        pos: 1,
        name: d.name || ROLE_NAME_FALLBACK,
        level: d.level,
        faceId: d.faceId,
        nationality: d.nationality,
        rankLevel: d.rankLevel,
        faceBorderId: d.faceBorderId,
        isOnline: true,
        isReady: true,
        pvpType,
      },
    ],
  };
  const parts = [Buffer.from([0x70])];
  emitRoomInfo(parts, info, 0);
  parts.push(Buffer.from([0x80, 0x80]));
  return Buffer.concat(parts);
}

/** Ambil field penting dari body Cmd_Room_Create_CS / Cmd_Room_Enter_CS. */
function parseRoomEnterCS(body) {
  const out = {
    roomId: null,
    enterSecret: null,
    pvpType: null,
    mapId: null,
    pvpMode: null,
  };
  if (!body || !body.length) return out;
  let nodes;
  try {
    nodes = sdp.decode(body);
  } catch (_) {
    return out;
  }
  const root = nodes.find((n) => n && n.type === sdp.T.STRUCT) || null;
  const fields = root ? root.fields : nodes;
  const intOf = (f) =>
    f && (f.type === sdp.T.INT || f.type === sdp.T.NEG) ? Number(f.v) : null;
  for (const f of fields) {
    if (!f || typeof f !== "object") continue;
    const tag = Number(f.tag);
    if (tag === 0) out.roomId = intOf(f);
    if (tag === 24 && f.type === sdp.T.STRING)
      out.enterSecret = f.raw.toString("utf8");
    if (tag === 3 || tag === 7) out.pvpType = intOf(f);
    if (tag === 8) out.mapId = intOf(f);
    if (tag === 9) out.pvpMode = intOf(f);
  }
  if (out.pvpType === null) {
    const tag1 = intOf(fields.find((f) => Number(f.tag) === 1));
    const tag0 = intOf(fields.find((f) => Number(f.tag) === 0));
    const candidate = tag1 !== null ? tag1 : tag0;
    if (candidate !== null && candidate >= 0 && candidate < 100)
      out.pvpType = candidate;
  }
  return out;
}

const ROLE_UID_FALLBACK = 332108113n;
const ROLE_NAME_FALLBACK = "petwir0x";

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
  buildLoginGetZoneSC,
  Cmd_Login_GetZone_CS,
  Cmd_Login_GetZone_SC,
  findAuthAccount,
  findAuthAccountById,
  getLastAccountId,
  setLastAccountId,
  createAuthAccount,
  registerAuthAccount,
  ROLE_INIT_FIELDS,
  ensureRoleInitFields,
  HERO_DATA_FIELDS,
  getCmdHeroData,
  getHeroGetList,
  upsertCmdHeroData,
  refreshHeroGetList,
  ensureHeroDataForAccount,
  setHeroCurrentSkin,
  HERO_SKIN_FIELDS,
  getCmdHeroSkin,
  getSkinGetList,
  upsertCmdHeroSkin,
  refreshSkinGetList,
  seedDefaultSkins,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  buildNetConnectSC,
  buildRoomEnterSCBody,
  buildRoomGetInfoSCBody,
  parseRoomEnterCS,
  AUTH_UID,
  packPacket,
};

if (require.main === module) {
  startAuthServer().then(() => startZoneServer());
}

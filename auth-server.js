const net = require("net");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
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

/**
 * Bungkus response (opcode/seq/body) ke amplop zstd seperti server resmi
 * (FR-1.2 / PROGRESS §2): `[10 00][total u16BE][zstd payload]`, payload =
 * `[opcode u32][seq][extra][0x46][varint bodyLen-1][body]`.
 */
function packZstdReply(opcode, seq, sdpBody, extra = Buffer.from([0x01])) {
  const inner = Buffer.concat([
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(opcode >>> 0, 0);
      return b;
    })(),
    Buffer.from([seq & 0xff]),
    extra,
    Buffer.from([0x46]),
    writeVarUint(sdpBody.length - 1),
    sdpBody,
  ]);
  const payload = zlib.zstdCompressSync(inner);
  const head = Buffer.alloc(4);
  head[0] = 0x10;
  head[1] = 0x00;
  head.writeUInt16BE(4 + payload.length, 2);
  return Buffer.concat([head, payload]);
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
  { tag: 6, field: "mMiscData", type: "map" },
  { tag: 7, field: "iLocalZoneId", type: "int" },
  { tag: 8, field: "iRegionId", type: "int" },
  { tag: 9, field: "sCountry", type: "string" },
  { tag: 10, field: "sUserIP", type: "string" },
  { tag: 11, field: "uiCreateAlt", type: "int" },
  { tag: 12, field: "uiConfirmNotOverrideFromZing", type: "int" },
  { tag: 13, field: "sUnityVersion", type: "string" },
  { tag: 14, field: "sDeviceInfo", type: "string" },
  { tag: 15, field: "mIDFAData", type: "map" },
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
  { tag: 33, field: "mNetEaseVerify", type: "map" },
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
 * Peta field Cmd_Login_CheckUpgrade_CS -> nomor tag SDP.
 * Field pertama di dump.cs (iAccountId, offset 0x10) memakai tag 0 dan
 * nomor tag naik satu per field declaration. vABTestExpParam adalah List.
 */
const CHECKUPGRADE_CS_TAG_FIELDS = [
  { tag: 0, field: "iAccountId", type: "int" },
  { tag: 1, field: "sSessionKey", type: "string" },
  { tag: 2, field: "sClientVersion", type: "string" },
  { tag: 3, field: "iZoneId", type: "int" },
  { tag: 4, field: "sChannel", type: "string" },
  { tag: 5, field: "sUserIP", type: "string" },
  { tag: 6, field: "iAccCreateTime", type: "int" },
  { tag: 7, field: "bHasAreaTag", type: "bool" },
  { tag: 8, field: "sCountry", type: "string" },
  { tag: 9, field: "iForceChangeAreaTagReason", type: "int" },
  { tag: 10, field: "iRoleLevel", type: "int" },
  { tag: 11, field: "iMemTag", type: "int" },
  { tag: 12, field: "iQuality", type: "int" },
  { tag: 13, field: "sCreateRoleCountry", type: "string" },
  { tag: 14, field: "vABTestExpParam", type: "list" },
  { tag: 15, field: "sMd5", type: "string" },
  { tag: 16, field: "iLoginId", type: "int" },
  { tag: 17, field: "iMagic", type: "int" },
  { tag: 18, field: "iOSType", type: "int" },
  { tag: 19, field: "bOpenFilterModuleVersion", type: "bool" },
  { tag: 20, field: "iSrcAppType", type: "int" },
  { tag: 21, field: "sUnityVersion", type: "string" },
  { tag: 22, field: "iClientDecompressionType", type: "int" },
  { tag: 23, field: "iClientSwitchFlag", type: "int" },
  { tag: 24, field: "iClientBenchScrore", type: "int" },
];

/** Cari definisi field Cmd_Login_CheckUpgrade_CS per nomor tag SDP. */
function getCheckUpgradeCsFieldDef(tag) {
  return CHECKUPGRADE_CS_TAG_FIELDS.find((c) => c.tag === tag);
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
    const parsedExtraFields = [];
    for (const f of root.fields) {
      const def = csFieldDef(f.tag);
      if (def) {
        if (def.type === "string") {
          cs[def.field] = f.type === sdp.T.STRING ? f.raw.toString("utf8") : "";
        } else if (def.type === "int" || def.type === "bool") {
          cs[def.field] =
            f.type === sdp.T.INT || f.type === sdp.T.NEG ? Number(f.v) : 0;
        } else if (def.type === "map") {
          const sub = {};
          if (f.type === sdp.T.MAP && Array.isArray(f.entries)) {
            for (const [k, v] of f.entries) {
              const key = typeof k?.v === "bigint" ? k.v.toString() : String(k);
              const val =
                v && (v.type === sdp.T.STRING || v.type === sdp.T.INT || v.type === sdp.T.NEG)
                  ? v.type === sdp.T.STRING
                    ? v.raw.toString("utf8")
                    : Number(v.v)
                  : "";
              sub[key] = val;
            }
          }
          cs[def.field] = sub;
        } else if (def.type === "struct") {
          const sub = {};
          if (f.type === sdp.T.STRUCT && Array.isArray(f.fields)) {
            for (const sf of f.fields) {
              sub[sf.tag] = sf.type === sdp.T.STRING ? sf.raw.toString("utf8") : Number(sf.v);
            }
          }
          cs[def.field] = sub;
        }
      }
      // Field di luar peta dump.cs: simpan agar tidak hilang tanpa nolah.
      if (!def) parsedExtraFields.push(f);
    }
    cs.parsedExtraFields = parsedExtraFields;
    return cs;
  }
}

/**
 * Emit struct CmdZoneInfo ke bagian body SDP. Begin struct memakai field tag-nya
 * (tag 2 -> byte 0x72, dst.); sub-field memakai tag naik-turut mulai 0.
 */
function emitZone(sdpParts, fieldTag, zone) {
  if (!zone) return;
  sdpParts.push(Buffer.from([(0x70 | fieldTag) & 0xff]));
  if (zone.iZoneId) sdpParts.push(packInt(0, BigInt(zone.iZoneId)));
  if (zone.sZoneName) sdpParts.push(packString(1, zone.sZoneName));
  if (zone.iStatus) sdpParts.push(packInt(2, BigInt(zone.iStatus)));
  if (zone.iFlag) sdpParts.push(packInt(3, BigInt(zone.iFlag)));
  if (zone.sVersion) sdpParts.push(packString(4, zone.sVersion));
  if (zone.sChannel) sdpParts.push(packString(5, zone.sChannel));
  if (zone.iMergeToZone) sdpParts.push(packInt(6, BigInt(zone.iMergeToZone)));
  if (zone.bIsMergeZone) sdpParts.push(packInt(7, 1));
  if (zone.iLastReportTime) sdpParts.push(packInt(8, BigInt(zone.iLastReportTime)));
  if (zone.iLastGameTime) sdpParts.push(packInt(9, BigInt(zone.iLastGameTime)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Emit list SDP: header tipe List + jumlah item + item. Item kosong -> count 0. */
function emitList(sdpParts, listTag, items, emitter) {
  if (!items || items.length === 0) {
    sdpParts.push(writeTag(listTag, 5), Buffer.from([0x00]));
    return;
  }
  sdpParts.push(writeTag(listTag, 5));
  sdpParts.push(writeVarUint(items.length));
  for (const item of items) emitter(sdpParts, item);
}

/** Emit struct CmdAccountInfo (dipakai list vAccountInfo). */
function emitAccountInfo(sdpParts, info) {
  if (!info) return;
  sdpParts.push(Buffer.from([0x70])); // StructBegin elemen list (tag 0)
  if (info.sAccountName) sdpParts.push(packString(0, info.sAccountName));
  if (info.mData) emitMapStr(sdpParts, 0, info.mData);
  if (info.iUnlockTime) sdpParts.push(packInt(2, BigInt(info.iUnlockTime)));
  if (info.iBanTime) sdpParts.push(packInt(3, BigInt(info.iBanTime)));
  if (info.iCanUnbindTime) sdpParts.push(packInt(4, BigInt(info.iCanUnbindTime)));
  if (info.bInterwork) sdpParts.push(packInt(5, 1));
  if (info.iInterworkOriOsType) sdpParts.push(packInt(6, BigInt(info.iInterworkOriOsType)));
  if (info.sUsaEmailToken) sdpParts.push(packString(7, info.sUsaEmailToken));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Emit list SimpleRoleInfo (dipakai vSimpleRoleInfo). */
function emitSimpleRoleInfo(sdpParts, info) {
  if (!info) return;
  sdpParts.push(Buffer.from([0x70])); // StructBegin elemen list (tag 0)
  if (info.iZoneID) sdpParts.push(packInt(0, BigInt(info.iZoneID)));
  if (info.iCreateRoleTime) sdpParts.push(packInt(1, BigInt(info.iCreateRoleTime)));
  if (info.iAreaTag) sdpParts.push(packInt(2, BigInt(info.iAreaTag)));
  if (info.bChangeName) sdpParts.push(packInt(3, 1));
  if (info.iCreateRoleAreaTag) sdpParts.push(packInt(4, BigInt(info.iCreateRoleAreaTag)));
  if (info.iLevel) sdpParts.push(packInt(5, BigInt(info.iLevel)));
  if (info.iForceChangeAreaTagReason) sdpParts.push(packInt(6, BigInt(info.iForceChangeAreaTagReason)));
  if (info.sCreateRoleCountry) sdpParts.push(packString(7, info.sCreateRoleCountry));
  if (info.vABTestExpParam && info.vABTestExpParam.length) {
    sdpParts.push(writeTag(8, 5));
    sdpParts.push(writeVarUint(info.vABTestExpParam.length));
    for (const entry of info.vABTestExpParam) sdpParts.push(packString(0, String(entry)));
  }
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

function emitAccountList(sdpParts, listTag, items) {
  emitList(sdpParts, listTag, items, emitAccountInfo);
}

function emitSimpleRoleList(sdpParts, listTag, items) {
  emitList(sdpParts, listTag, items, emitSimpleRoleInfo);
}

/** Emit map<string, string> (Map) ke body SDP. */
function emitMapStr(sdpParts, mapTag, map) {
  if (!map) return;
  const entries = Object.entries(map).filter(
    ([, v]) => v !== undefined && v !== null && v !== "",
  );
  if (entries.length === 0) return;
  sdpParts.push(Buffer.from([(6 << 4) | mapTag]));
  sdpParts.push(writeVarUint(entries.length));
  for (const [k, v] of entries) {
    sdpParts.push(packString(0, String(k)));
    sdpParts.push(packString(0, String(v)));
  }
}

/** Emit map<integer, string> ke body SDP. */
function emitMapIntStr(sdpParts, mapTag, map) {
  if (!map) return;
  const entries = Object.entries(map)
    .map(([k, v]) => [Number(k), v])
    .filter(([k, v]) => Number.isFinite(k) && v !== undefined && v !== null && v !== "");
  if (entries.length === 0) return;
  sdpParts.push(Buffer.from([(6 << 4) | mapTag]));
  sdpParts.push(writeVarUint(entries.length));
  for (const [k, v] of entries) {
    sdpParts.push(packInt(0, BigInt(k)));
    sdpParts.push(packString(0, String(v)));
  }
}

/** Emit struct CmdUnregInfo ke body SDP. */
function emitUnregInfo(sdpParts, info) {
  if (!info) return;
  sdpParts.push(Buffer.from([(0x70 | 17) & 0xff])); // StructBegin tag 17
  if (info.iStatus) sdpParts.push(packInt(0, BigInt(info.iStatus)));
  if (info.vRole && info.vRole.length) {
    sdpParts.push(writeTag(1, 5));
    sdpParts.push(writeVarUint(info.vRole.length));
    for (const v of info.vRole) sdpParts.push(packInt(0, BigInt(v)));
  }
  if (info.vFailReason && info.vFailReason.length) {
    sdpParts.push(writeTag(2, 5));
    sdpParts.push(writeVarUint(info.vFailReason.length));
    for (const v of info.vFailReason) sdpParts.push(packInt(0, BigInt(v)));
  }
  if (info.iUnregExceTime) sdpParts.push(packInt(3, BigInt(info.iUnregExceTime)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
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
    this.stMergingZone = account.stMergingZone || null;
    this.stOtherRoleZone = account.stOtherRoleZone || null;
    this.stNewestZone = account.stNewestZone || null;
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
    this.stUnregInfo = account.stUnregInfo || null;
    this.sState = account.sState || "";
    this.iAccCreateTime = account.iAccCreateTime ?? 1793530475;
    this.vSimpleRoleInfo = account.vSimpleRoleInfo || [];
    this.iTimeGmtOff = account.iTimeGmtOff ?? 0n;
    this.mapConfig = account.mapConfig || null;
    this.stUnbindData = account.stUnbindData || null;
    this.bIsFlowBack = !!account.bIsFlowBack;
    this.mErrorParam = account.mErrorParam || null;
    this.mapConfigWithIntKey = account.mapConfigWithIntKey || null;
    this.sLoginAccToken = account.sLoginAccToken || "";
    this.sMd5 = account.sMd5 || "";
    this.mapConfigV2 = account.mapConfigV2 || null;
    this.bClearLoginAccToken = !!account.bClearLoginAccToken;
    this.iSharkResult = account.iSharkResult ?? 0;
    this.iNetEaseResult = account.iNetEaseResult ?? 0;
    this.iAccountServerFlag = account.iAccountServerFlag ?? 0;
  }

  /** Bungkus field akun menjadi body SDP untuk Cmd_Login_Auth_SC. */
  toSdpBody() {
    const a = this;
    const sdpParts = [];
    sdpParts.push(Buffer.from([0x70])); // StructBegin

    // Catatan: field pertama response Auth SC dari server resmi adalah tag 1
    // (sSessionKey). Field tag 0 di level root TIDAK boleh dipakai karena tumpang
    // tindih dengan StructBegin tag 0 -> parser C# (SdpUnpacker) error "unknown type".
    // (iAccountId sengaja tidak dikirim, mengikuti perilaku server resmi.)

    // Tag 1: sSessionKey
    if (a.sSessionKey) sdpParts.push(packString(1, a.sSessionKey));

    // Tag 2: stZone (CmdZoneInfo struct)
    {
      const z = a.stZone || {};
      sdpParts.push(Buffer.from([0x72])); // StructBegin stZone (Tag 2)
      if (z.iZoneId) sdpParts.push(packInt(0, BigInt(z.iZoneId)));
      if (z.sZoneName) sdpParts.push(packString(1, z.sZoneName));
      if (z.iStatus) sdpParts.push(packInt(2, BigInt(z.iStatus)));
      if (z.iFlag) sdpParts.push(packInt(3, BigInt(z.iFlag)));
      if (z.sVersion) sdpParts.push(packString(4, z.sVersion));
      if (z.sChannel) sdpParts.push(packString(5, z.sChannel));
      if (z.iMergeToZone) sdpParts.push(packInt(6, BigInt(z.iMergeToZone)));
      if (z.bIsMergeZone) sdpParts.push(packInt(7, 1));
      if (z.iLastReportTime) sdpParts.push(packInt(8, BigInt(z.iLastReportTime)));
      if (z.iLastGameTime) sdpParts.push(packInt(9, BigInt(z.iLastGameTime)));
      sdpParts.push(Buffer.from([0x80])); // StructEnd stZone
    }

    // Tag 3: vAccountInfo (List<CmdAccountInfo>)
    emitAccountList(sdpParts, 3, a.vAccountInfo);

    // Tag 4-6: stMergingZone / stOtherRoleZone / stNewestZone (CmdZoneInfo)
    emitZone(sdpParts, 4, a.stMergingZone);
    emitZone(sdpParts, 5, a.stOtherRoleZone);
    emitZone(sdpParts, 6, a.stNewestZone);

    // Tag 7-9: sUserIP / sAccountName / sCountry
    if (a.sUserIP) sdpParts.push(packString(7, a.sUserIP));
    if (a.sAccountName) sdpParts.push(packString(8, a.sAccountName));
    if (a.sCountry) sdpParts.push(packString(9, a.sCountry));

    // Tag 10: iServerTimeMS (UInt64 -> BigInt)
    if (a.iServerTimeMS) sdpParts.push(packInt(10, BigInt(a.iServerTimeMS)));

    // Tag 11-14
    if (a.bLocalZoneHasMerged) sdpParts.push(packInt(11, 1)); // bLocalZoneHasMerged
    if (a.bNewAccount) sdpParts.push(packInt(12, 1)); // bNewAccount
    if (a.iAccountFlag) sdpParts.push(packInt(13, BigInt(a.iAccountFlag))); // iAccountFlag
    if (a.uiCreateAlt) sdpParts.push(packInt(14, BigInt(a.uiCreateAlt))); // uiCreateAlt

    // Tag 15: sIsp
    if (a.sIsp) sdpParts.push(packString(15, a.sIsp));

    // Tag 16: mapConfig (Map<String, String>)
    if (a.mapConfig) emitMapStr(sdpParts, 16, a.mapConfig);

    // Tag 17: stUnregInfo (CmdUnregInfo)
    emitUnregInfo(sdpParts, a.stUnregInfo);

    // Tag 18: sState
    if (a.sState) sdpParts.push(packString(18, a.sState));

    // Tag 19: iAccCreateTime
    if (a.iAccCreateTime) sdpParts.push(packInt(19, BigInt(a.iAccCreateTime)));

    // Tag 20: vSimpleRoleInfo (List<SimpleRoleInfo>)
    emitSimpleRoleList(sdpParts, 20, a.vSimpleRoleInfo);

    // Tag 21: iTimeGmtOff (Int64, bisa negatif)
    if (a.iTimeGmtOff) sdpParts.push(packInt(21, BigInt(a.iTimeGmtOff)));

    // Tag 22: stUnbindData (CmdDeviceUnbindData)
    if (a.stUnbindData) {
      const u = a.stUnbindData;
      sdpParts.push(Buffer.from([0x7e])); // StructBegin tag 22 (0x70 | 22)
      if (u.iUnbindReason) sdpParts.push(packInt(0, BigInt(u.iUnbindReason)));
      sdpParts.push(Buffer.from([0x80])); // StructEnd
    }

    // Tag 23: bIsFlowBack
    if (a.bIsFlowBack) sdpParts.push(packInt(23, 1));
    // Tag 24: mErrorParam (Map<String, String>)
    if (a.mErrorParam) emitMapStr(sdpParts, 24, a.mErrorParam);
    // Tag 25: mapConfigWithIntKey (Map<Integer, String>)
    if (a.mapConfigWithIntKey) emitMapIntStr(sdpParts, 25, a.mapConfigWithIntKey);
    // Tag 26: sLoginAccToken
    if (a.sLoginAccToken) sdpParts.push(packString(26, a.sLoginAccToken));
    // Tag 27: sMd5
    if (a.sMd5) sdpParts.push(packString(27, a.sMd5));
    // Tag 28: mapConfigV2 (Map<String, String>)
    if (a.mapConfigV2) emitMapStr(sdpParts, 28, a.mapConfigV2);
    // Tag 29: bClearLoginAccToken
    if (a.bClearLoginAccToken) sdpParts.push(packInt(29, 1));
    // Tag 30: iSharkResult
    if (a.iSharkResult) sdpParts.push(packInt(30, BigInt(a.iSharkResult)));
    // Tag 31: iNetEaseResult
    if (a.iNetEaseResult) sdpParts.push(packInt(31, BigInt(a.iNetEaseResult)));
    // Tag 32: iAccountServerFlag
    if (a.iAccountServerFlag) sdpParts.push(packInt(32, BigInt(a.iAccountServerFlag)));

    sdpParts.push(Buffer.from([0x80])); // StructEnd utama
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
 * Cmd_Login_CheckUpgrade_CS: paket dari client (Cmd_Login_CheckUpgrade_CS,
 * opcode 0x70000501) setelah diurai dari body SDP. Field yang tidak ada di body
 * hanya diisi default kosong, supaya pemanggilan dari field lain tetap aman.
 */
class Cmd_Login_CheckUpgrade_CS {
  constructor() {
    this.iAccountId = 0;
    this.sSessionKey = "";
    this.sClientVersion = "";
    this.iZoneId = 0;
    this.sChannel = "";
    this.sUserIP = "";
    this.iAccCreateTime = 0;
    this.bHasAreaTag = false;
    this.sCountry = "";
    this.iForceChangeAreaTagReason = 0;
    this.iRoleLevel = 0;
    this.iMemTag = 0;
    this.iQuality = 0;
    this.sCreateRoleCountry = "";
    this.vABTestExpParam = [];
    this.sMd5 = "";
    this.iLoginId = 0;
    this.iMagic = 0;
    this.iOSType = 0;
    this.bOpenFilterModuleVersion = false;
    this.iSrcAppType = 0;
    this.sUnityVersion = "";
    this.iClientDecompressionType = 0;
    this.iClientSwitchFlag = 0;
    this.iClientBenchScrore = 0;
  }

  /**
   * Urai body SDP menjadi instance Cmd_Login_CheckUpgrade_CS.
   * Body berbentuk root struct (tag 0) + StructEnd.
   */
  static fromSdpBody(body) {
    const cs = new Cmd_Login_CheckUpgrade_CS();
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
      const def = getCheckUpgradeCsFieldDef(f.tag);
      if (!def) continue;
      if (def.type === "string") {
        cs[def.field] = f.type === sdp.T.STRING ? f.raw.toString("utf8") : "";
      } else if (def.type === "int" || def.type === "bool") {
        cs[def.field] =
          f.type === sdp.T.INT || f.type === sdp.T.NEG ? Number(f.v) : 0;
      } else if (def.type === "list") {
        const arr = [];
        if (f.type === sdp.T.LIST && Array.isArray(f.items)) {
          for (const it of f.items) {
            arr.push(
              it && it.type === sdp.T.STRING
                ? it.raw.toString("utf8")
                : String((it && it.v) ?? ""),
            );
          }
        }
        cs[def.field] = arr;
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
    this.vRoleList = [];
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

    // Tag 1: vRoleList (List) -> kosong
    sdpParts.push(Buffer.from([0x51, 0x00])); // Type 5 (List) tag 1, jumlah item 0

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

// Migrasi ringan: pastikan kolom i_region_id ada pada database lama.
{
  const cols = AUTH_DB.prepare("PRAGMA table_info(auth_accounts)").all();
  if (!cols.some((c) => c.name === "i_region_id")) {
    AUTH_DB.exec(
      "ALTER TABLE auth_accounts ADD COLUMN i_region_id INTEGER NOT NULL DEFAULT 0;",
    );
  }
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
  return authAccountFromRow(row);
}

/**
 * Build Cmd_Login_Auth_SC (opcode 0x70000201) untuk seq tertentu.
 * Akun dipakai bila tersedia (hasil lookup database/toko auth), supaya field
 * auth (iAccountId, sSessionKey, stZone, flag akun) sesuai akun yang login.
 * Response dibungkus amplop zstd seperti server resmi (FR-1.2 / PROGRESS §2).
 */
function buildLoginAuthSC(seq, account = DEFAULT_LOGIN_AUTH_ACCOUNT) {
  const sc = new Cmd_Login_Auth_SC(account);
  const sdpBody = sc.toSdpBody();
  return packZstdReply(0x70000201, seq, sdpBody);
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
 * Emit struct CmdModuleVersion (dipakai list di dalam CmdLoginCheckUpgrade_SC).
 */
function emitModuleVersion(sdpParts, moduleInfo) {
  if (!moduleInfo) return;
  sdpParts.push(Buffer.from([0x70])); // StructBegin elemen list (tag 0)
  if (moduleInfo.sModuleName) sdpParts.push(packString(0, moduleInfo.sModuleName));
  if (moduleInfo.sModuleVersion) sdpParts.push(packString(1, moduleInfo.sModuleVersion));
  if (moduleInfo.iDownloadMaxTime) sdpParts.push(packInt(2, BigInt(moduleInfo.iDownloadMaxTime)));
  if (moduleInfo.bGrayReference) sdpParts.push(packInt(3, 1));
  if (moduleInfo.sBasicVersion) sdpParts.push(packString(4, moduleInfo.sBasicVersion));
  if (moduleInfo.iPriority) sdpParts.push(packInt(5, BigInt(moduleInfo.iPriority)));
  if (moduleInfo.sClientPrivate) sdpParts.push(packString(6, moduleInfo.sClientPrivate));
  if (moduleInfo.iConfigId) sdpParts.push(packInt(7, BigInt(moduleInfo.iConfigId)));
  if (moduleInfo.iRoleLevelMax) sdpParts.push(packInt(8, BigInt(moduleInfo.iRoleLevelMax)));
  if (moduleInfo.iRoleLevelMin) sdpParts.push(packInt(9, BigInt(moduleInfo.iRoleLevelMin)));
  if (moduleInfo.iDownloadPriority) sdpParts.push(packInt(10, BigInt(moduleInfo.iDownloadPriority)));
  if (moduleInfo.iIsLoginSend) sdpParts.push(packInt(11, BigInt(moduleInfo.iIsLoginSend)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Emit struct CmdABTestConfig. */
function emitABTestConfig(sdpParts, cfg) {
  if (!cfg) return;
  sdpParts.push(Buffer.from([0x70])); // StructBegin elemen list (tag 0)
  if (cfg.sParamName) sdpParts.push(packString(0, cfg.sParamName));
  if (cfg.sParamValue) sdpParts.push(packString(1, cfg.sParamValue));
  if (cfg.iExpiryDate) sdpParts.push(packInt(2, BigInt(cfg.iExpiryDate)));
  sdpParts.push(Buffer.from([0x80])); // StructEnd
}

/** Emit CmdABTestInfo (List<CmdABTestConfig>). */
function emitABTest(sdpParts, abTest) {
  if (!abTest) return;
  emitList(sdpParts, 0, abTest.vParam || [], emitABTestConfig);
}

/**
 * Cmd_Login_CheckUpgrade_SC dengan CDN Asli Moonton
 * Mengarahkan sConnServer ke port Zone 30101
 */
class Cmd_Login_CheckUpgrade_SC {
  constructor(opts = {}) {
    this.iZoneId = opts.iZoneId ?? 57102;
    this.sConnServer = opts.sConnServer ?? `${SERVER_IP}:${ZONE_PORT}`;
    this.sClientVersion = opts.sClientVersion ?? "2.2.30.1154.1";
    this.sResPatchVersion = opts.sResPatchVersion ?? "";
    this.sResAllVersion = opts.sResAllVersion ?? "";
    this.sCdnVersion = opts.sCdnVersion ?? "1";
    this.sApkUpdateAddr = opts.sApkUpdateAddr ?? "https://www.taptap.io/app/33653913";
    this.sForceVersion = opts.sForceVersion ?? "2.1.0";
    this.sFaceCdnHost = opts.sFaceCdnHost ?? "";
    this.sFaceUploadHost = opts.sFaceUploadHost ?? "";
    this.sFaceCdnHostNew = opts.sFaceCdnHostNew ?? "";
    const patchUrls =
      "http://akmcdn.ml.youngjoygame.com/res_patch/;http://akmcdn.ml.youngjoygame.com/res_patch/;http://pldtcdn.ml.youngjoygame.com/res_patch/;http://wscdn.ml.youngjoygame.com/res_patch/";
    const allUrls =
      "http://akmcdn.ml.youngjoygame.com/res_version/;http://akmcdn.ml.youngjoygame.com/res_version/;http://pldtcdn.ml.youngjoygame.com/res_version/;http://wscdn.ml.youngjoygame.com/res_version/";
    this.sResPatchVersionNew = opts.sResPatchVersionNew ?? patchUrls;
    this.sResAllVersionNew = opts.sResAllVersionNew ?? allUrls;
    this.sNewConnServerList = opts.sNewConnServerList ?? `${this.sConnServer};8.219.169.192:30102`;
    this.iRetryNum = opts.iRetryNum ?? 3;
    this.sSignature = opts.sSignature ?? "d659c5397a8f2a5b6f3489e546a389ca54fd28fc,eda6413c3e3a95492114fe07cd953ad897e40d1a";
    this.sPhotoCdnHost = opts.sPhotoCdnHost ?? "";
    this.sForceUpdateUrl = opts.sForceUpdateUrl ?? "https://www.taptap.io/app/33653913";
    this.sCdnVersion = opts.sCdnVersion ?? "1";
    this.sCdnHostNewResAllVersionArray = opts.sCdnHostNewResAllVersionArray ?? "";
    this.sCdnHostNewResPatchVersionArray = opts.sCdnHostNewResPatchVersionArray ?? "";
    this.vModuleVersion = opts.vModuleVersion ?? [];
    this.iModuleVersionUpdateTime = opts.iModuleVersionUpdateTime ?? 0;
    this.iAreaTag = opts.iAreaTag ?? 0;
    this.stABTest = opts.stABTest ?? null;
  }

  /** Bungkus field CheckUpgrade menjadi body SDP. */
  toSdpBody() {
    const s = this;
    const sdpParts = [];
    sdpParts.push(Buffer.from([0x70])); // StructBegin

    if (s.iZoneId) sdpParts.push(packInt(0, BigInt(s.iZoneId)));
    if (s.sConnServer) sdpParts.push(packString(1, s.sConnServer));
    if (s.sClientVersion) sdpParts.push(packString(2, s.sClientVersion));
    if (s.sResPatchVersion) sdpParts.push(packString(3, s.sResPatchVersion));
    if (s.sResAllVersion) sdpParts.push(packString(4, s.sResAllVersion));
    if (s.sCdnVersion) sdpParts.push(packString(5, s.sCdnVersion));
    if (s.sApkUpdateAddr) sdpParts.push(packString(6, s.sApkUpdateAddr));
    if (s.sForceVersion) sdpParts.push(packString(7, s.sForceVersion));
    if (s.sFaceCdnHost) sdpParts.push(packString(8, s.sFaceCdnHost));
    if (s.sFaceUploadHost) sdpParts.push(packString(9, s.sFaceUploadHost));
    if (s.sFaceCdnHostNew) sdpParts.push(packString(10, s.sFaceCdnHostNew));
    if (s.sResPatchVersionNew) sdpParts.push(packString(11, s.sResPatchVersionNew));
    if (s.sResAllVersionNew) sdpParts.push(packString(12, s.sResAllVersionNew));
    if (s.sNewConnServerList) sdpParts.push(packString(13, s.sNewConnServerList));
    if (s.iRetryNum) sdpParts.push(packInt(14, BigInt(s.iRetryNum)));
    if (s.sSignature) sdpParts.push(packString(15, s.sSignature));
    if (s.sPhotoCdnHost) sdpParts.push(packString(16, s.sPhotoCdnHost));
    if (s.sForceUpdateUrl) sdpParts.push(packString(17, s.sForceUpdateUrl));
    if (s.sCdnVersion) sdpParts.push(packString(18, s.sCdnVersion));
    if (s.sCdnHostNewResAllVersionArray) sdpParts.push(packString(19, s.sCdnHostNewResAllVersionArray));
    if (s.sCdnHostNewResPatchVersionArray) sdpParts.push(packString(20, s.sCdnHostNewResPatchVersionArray));
    emitList(sdpParts, 21, s.vModuleVersion, emitModuleVersion);
    if (s.iModuleVersionUpdateTime) sdpParts.push(packInt(22, BigInt(s.iModuleVersionUpdateTime)));
    if (s.iAreaTag) sdpParts.push(packInt(23, BigInt(s.iAreaTag)));
    if (s.stABTest) emitABTest(sdpParts, s.stABTest);
    sdpParts.push(Buffer.from([0x80])); // StructEnd
    return Buffer.concat(sdpParts);
  }
}

function buildLoginCheckUpgradeSC(seq, opts = {}) {
  const sc = new Cmd_Login_CheckUpgrade_SC(opts);
  const sdpBody = sc.toSdpBody();
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
        const fs = require("fs");
        const rawBody = fs.readFileSync("/tmp/opencode/cache_body.bin");
        const zpkg = packZstdReply(0x70000201, seq, rawBody);
        console.log(`[AUTH:30021] Auth_SC zstd reply: ${zpkg.length}B`);
        sock.write(zpkg);
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
  buildLoginGetZoneSC,
  Cmd_Login_GetZone_CS,
  Cmd_Login_GetZone_SC,
  findAuthAccount,
  findAuthAccountById,
  createAuthAccount,
  registerAuthAccount,
  buildLoginGetBulletinSC,
  buildLoginCheckUpgradeSC,
  Cmd_Login_CheckUpgrade_CS,
  buildNetConnectSC,
  packPacket,
  packZstdReply,
};

if (require.main === module) {
  startAuthServer().then(() => startZoneServer());
}

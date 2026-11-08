import "frida-il2cpp-bridge";

// ====================================================================
// CONFIG
// ====================================================================
const TARGET_LIB = "liblogic.so";
const MAX_RECV_BYTES = 64 * 1024;
Il2Cpp.$config.moduleName = TARGET_LIB;

const OPCODE_NAMES = {
  0x70000101: "Cmd_Login_Auth_CS",
  0x70000201: "Cmd_Login_Auth_SC",
  0x70000301: "Cmd_Login_GetZone_CS",
  0x70000401: "Cmd_Login_GetZone_SC",
  0x70000501: "Cmd_Login_CheckUpgrade_CS",
  0x70000601: "Cmd_Login_CheckUpgrade_SC",
  0x70000701: "Cmd_Login_GetBulletin_CS",
  0x70000801: "Cmd_Login_GetBulletin_SC",
  0x70000d01: "Cmd_Login_Echo_CS",
  0x70000e01: "Cmd_Login_Echo_SC",
  0x7000914e: "Cmd_Net_Connect_CS",
  0x7000924e: "Cmd_Net_Connect_SC",
  0x7000954e: "Cmd_Net_Echo_SC",
  0x7000964e: "Cmd_Net_ServerTime_SC",
  0x7000974e: "Cmd_Role_Init_CS",
  0x7000984e: "Cmd_Role_Init_SC",
};

// ====================================================================
// HELPERS
// ====================================================================
function hex(n) {
  return "0x" + (n >>> 0).toString(16);
}

// Opcode pesan yang sedang di-unpack per thread. visit() dipanggil DI DALAM
// PackUtil.Unpack(), jadi nilai ini menempelkan setiap tag ke opcode pemiliknya.
const currentOpcode = new Map();

// Opcode WIRE (0x70xxxxxx) untuk pesan yang sedang didekode di thread ini.
// Diisi dari 4 byte pertama buffer DecodeMsgBody, dipakai oleh hook Unpack.
const currentWireOpcode = new Map();

// Penanda panggilan PackUtil.Unpack yang sedang berjalan per thread. Nilai ini
// ditempelkan ke event `visit` dan `unpack_class` sehingga field body bisa
// dikelompokkan tepat ke class pemiliknya (tanpa menebak waktu).
let unpackCallSeq = 0;
const currentUnpackCall = new Map();
const unpackDepth = new Map();

// Peta nama class -> daftar field (nama + tipe) dibangun saat start.
let classFieldMap = null;

/**
 * Ambil opcode wire dari buffer frame. Beberapa jalur mengirim tanpa prefix
 * panjang (opcode di byte 0), sebagian dengan prefix 4 byte (opcode di byte 4).
 */
function wireOpcodeFrom(raw) {
  try {
    if (!raw) return null;
    const b = new Uint8Array(raw);
    if (b.length >= 4 && b[0] === 0x70) {
      return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    }
    if (b.length >= 8 && b[4] === 0x70) {
      return ((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) >>> 0;
    }
  } catch (_) {}
  return null;
}

// Referensi ke class NetUtil.PackUtil, diisi saat hook dipasang. Dipakai untuk
// membaca field static `res` (RspProto) yang menyimpan iRspCmdId = opcode wire.
let packUtilClass = null;

/**
 * Cek kasar apakah pointer aman untuk dibaca: tidak null, cukup besar, dan
 * selaras. Mencegah access violation saat layout struct beda antar build.
 */
function isValidPtr(p) {
  try {
    if (!p || p.isNull()) return false;
    const n = p.toUInt64();
    return n.compare(0x10000) >= 0 && n.compare(0x00007ffffff00000) < 0 && n.and(7).compare(0) === 0;
  } catch (_) {
    return false;
  }
}

/**
 * Opcode wire dari static PackUtil.res.iRspCmdId. Ini sumber paling langsung:
 * DecodeMsgBody mengisi `res` sebelum body di-Unpack, jadi saat Unpack berjalan
 * nilainya masih milik paket yang sedang diproses.
 */
function opcodeFromRes() {
  try {
    if (!packUtilClass) return null;
    const resField = packUtilClass.tryField("res");
    if (!resField) return null;
    const res = resField.value;
    if (!res || res.isNull()) return null;
    const f = res.tryField("iRspCmdId");
    if (!f) return null;
    const v = f.value;
    const n = typeof v === "number" ? v : Number(v);
    if (!Number.isFinite(n)) return null;
    const u = n >>> 0;
    return u >>> 24 === 0x70 ? u : null;
  } catch (_) {
    return null;
  }
}

/**
 * Ambil ReturnMsg.messageid dari argumen Unpack. Posisi ReturnMsg berbeda
 * antara metode static (arg 1) dan instance (this di arg 0, Type arg 1,
 * ReturnMsg arg 2), jadi coba keduanya lalu terima hanya nilai berformat
 * opcode game (byte teratas 0x70).
 */
function pickOpcode(args) {
  for (const i of [1, 2]) {
    const v = msgIdFrom(args[i]);
    if (v !== null) return v;
  }
  return null;
}

/**
 * Baca ReturnMsg.messageid lewat metadata il2cpp (bukan offset keras), karena
 * offset field bisa beda antar build. Mengembalikan null bila objek bukan
 * ReturnMsg (mis. argumen itu System.Type).
 */
function msgIdFrom(p) {
  try {
    if (!p || p.isNull()) return null;
    const obj = new Il2Cpp.Object(p);
    const f = obj.tryField("messageid");
    if (!f) return null;
    const v = f.value;
    if (typeof v === "number") return v >>> 0;
    if (v && typeof v.toNumber === "function") return v.toNumber() >>> 0;
    return null;
  } catch (_) {
    return null;
  }
}

function findGlobalExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === "function")
      return Module.findGlobalExportByName(name); // Frida 17+
    if (typeof Module.findExportByName === "function")
      return Module.findExportByName(null, name); // Frida <= 16
  } catch (_) {}
  return null;
}

function findExport(mod, name) {
  try {
    if (typeof mod.findExportByName === "function")
      return mod.findExportByName(name);
    return mod.getExportByName(name);
  } catch (_) {
    return null;
  }
}

// Mengubah field objek SDP menjadi objek JSON biasa
function collectFields(instance) {
  const out = {};
  try {
    if (!instance || instance.isNull()) return out;
    instance.class.fields.forEach((f) => {
      if (f.isStatic) return;
      try {
        const val = instance.field(f.name).value;
        let v = null;
        if (val !== null && val !== undefined) {
          if (typeof val === "object" && val.isNull && val.isNull()) v = null;
          else if (typeof val === "object" && val.content !== undefined)
            v = val.content;
          else if (typeof val === "number" || typeof val === "boolean") v = val;
          else v = String(val);
        }
        out[f.name] = { type: f.type.name, value: v };
      } catch (_) {}
    });
  } catch (_) {}
  return out;
}

// ====================================================================
// HOOKS
// ====================================================================
function executeSimpleHooks() {
  console.log("[*] Memasang hook SDP Packet & Tag Inspector...");

  const image = Il2Cpp.domain.assembly("Assembly-CSharp").image;

  // ---- 1. RECV: NetUtil.PackUtil.DecodeMsgBody ----
  try {
    const decodeMethod = image
      .class("NetUtil.PackUtil")
      .method("DecodeMsgBody");

    // DecodeMsgBody(...) bisa static (val di arg 0) atau instance (this di arg 0).
    const decodeArgShift = decodeMethod.isStatic ? 0 : 1;

    Interceptor.attach(decodeMethod.virtualAddress, {
      onEnter(args) {
        this.raw = null;
        this.tid = Process.getCurrentThreadId();
        if (!globalThis.__dbgDecode) {
          globalThis.__dbgDecode = true;
          try {
            send({
              kind: "debug",
              direction: "DBG",
              where: "DecodeMsgBody",
              isStatic: decodeMethod.isStatic,
              paramCount: decodeMethod.parameterCount,
              params: decodeMethod.parameters.map((p) => p.type.name),
              args: [0, 1, 2, 3].map((i) =>
                args[i] ? args[i].toString() : "none",
              ),
              shift: decodeArgShift,
            });
          } catch (_) {}
        }
        try {
          const valArrayPtr = args[decodeArgShift];
          const iRecvLen = args[decodeArgShift + 1].toInt32();
          const uiStartPos = args[decodeArgShift + 2].toUInt32();

          if (!valArrayPtr.isNull() && iRecvLen > 0) {
            const dataOffset = Process.pointerSize === 8 ? 0x20 : 0x10;
            const bufferPtr = valArrayPtr.add(dataOffset).add(uiStartPos);
            this.raw = bufferPtr.readByteArray(
              Math.min(iRecvLen, MAX_RECV_BYTES),
            );
            const op = wireOpcodeFrom(this.raw);

            // Kirim RAW RECV langsung dari onEnter. ReturnMsg (retval) ternyata
            // bukan pointer valid di build ini, jadi jangan menunggu onLeave.
            send(
              {
                kind: "packet",
                direction: "RECV",
                opcode: op !== null ? hex(op) : "0x0",
                opcode_wire: op !== null ? hex(op) : null,
                opcode_name: "UnknownOpcode",
                class_name: "None / Raw",
                seq: null,
                rsp_code: null,
                timestamp: Date.now(),
                fields: {},
              },
              this.raw,
            );

            if (op !== null) {
              this.wireOpcode = hex(op);
              currentWireOpcode.set(this.tid, this.wireOpcode);
              // Event eksplisit untuk mencocokkan dengan class hasil Unpack
              // berdasarkan urutan/waktu (body bisa didekode di thread lain).
              send({
                kind: "wire_opcode",
                direction: "OP",
                opcode: this.wireOpcode,
                thread: this.tid,
                timestamp: Date.now(),
              });
            }
          }
        } catch (_) {}
      },
      onLeave(retval) {
        // RECV sudah dikirim dari onEnter (raw + opcode). retval adalah
        // ReturnMsg hasil decode; pada build ini layout-nya sama dengan
        // ReturnMsg yang diterima Unpack: messageid@0, rspcode@4, rspseq@8.
        try {
          if (this.wireOpcode && retval && !retval.isNull()) {
            const msgId = retval.readU32();
            if (msgId !== 0 && msgId !== 0xffffffff) {
              send({
                kind: "wire_msgid",
                direction: "MSGID",
                opcode: this.wireOpcode,
                msg_id: hex(msgId),
                rsp_code: retval.add(4).readS32(),
                rsp_seq: retval.add(8).readU32(),
                thread: this.tid,
                timestamp: Date.now(),
              });
            }
          }
        } catch (e) {
          if (!globalThis.__dbgMsgId) {
            globalThis.__dbgMsgId = true;
            send({ kind: "debug", where: "wire_msgid.err", err: String(e) });
          }
        }
        try {
          currentWireOpcode.delete(this.tid);
        } catch (_) {}
      },
    });
    console.log("[✓] Hooked NetUtil.PackUtil.DecodeMsgBody");
  } catch (e) {
    console.warn("[!] Gagal hook DecodeMsgBody: " + (e && e.message));
  }

  // ---- 1b. RECV: GameServerConfig.onMsgBodyCallback(GameSocketType, byte[], int, int) ----
  // Titik masuk SEMUA paket masuk sebelum di-parse. Buffer mentah di sini masih
  // memuat opcode wire, jadi thread-local ini yang dipakai hook visit/Unpack.
  try {
    const gscClass = image.class("GameServerConfig");
    const cb = gscClass.methods.find(
      (m) => m.name === "onMsgBodyCallback" && m.parameterCount === 4,
    );
    if (!cb) throw new Error("method onMsgBodyCallback tidak ditemukan");
    const cbShift = cb.isStatic ? 0 : 1;

    Interceptor.attach(cb.virtualAddress, {
      onEnter(args) {
        this.tid = Process.getCurrentThreadId();
        this.prev = currentWireOpcode.get(this.tid) || null;
        try {
          const arrPtr = args[cbShift + 1];
          const start = args[cbShift + 2].toInt32();
          const netSize = args[cbShift + 3].toInt32();
          if (arrPtr.isNull() || netSize <= 0) return;
          const dataOffset = Process.pointerSize === 8 ? 0x20 : 0x10;
          const raw = arrPtr
            .add(dataOffset)
            .add(start)
            .readByteArray(Math.min(netSize, 64));
          const op = wireOpcodeFrom(raw);
          if (op !== null) {
            currentWireOpcode.set(this.tid, hex(op));
            if (!globalThis.__dbgBody) {
              globalThis.__dbgBody = true;
              send({
                kind: "debug",
                where: "onMsgBodyCallback",
                opcode: hex(op),
                start: start,
                netSize: netSize,
                shift: cbShift,
                params: cb.parameters.map((p) => p.type.name),
                timestamp: Date.now(),
              });
            }
          }
        } catch (_) {}
      },
      onLeave() {
        try {
          if (this.prev) currentWireOpcode.set(this.tid, this.prev);
          else currentWireOpcode.delete(this.tid);
        } catch (_) {}
      },
    });
    console.log("[✓] Hooked GameServerConfig.onMsgBodyCallback");
  } catch (e) {
    console.warn("[!] Gagal hook onMsgBodyCallback: " + (e && e.message));
  }

  // ---- 2. SEND ----
  // 2a. send_msg(id, SdpWrapper, no_response): simpan field SDP sebagai konteks.
  //     Byte aslinya baru ada setelah SdpPackerImpl.pack() (2b).
  const pendingSend = {}; // msgId -> { className, fields }

  try {
    const sendSdp = image
      .class("GameService.GameClient")
      .methods.find((m) => m.name === "send_msg" && m.parameterCount === 3);

    if (sendSdp) {
      Interceptor.attach(sendSdp.virtualAddress, {
        onEnter(args) {
          try {
            const msgId = args[1].toUInt32();
            let className = "Unknown";
            let fields = {};
            if (!args[2].isNull()) {
              try {
                const o = new Il2Cpp.Object(args[2]);
                className = o.class.name;
                fields = collectFields(o);
              } catch (_) {}
            }
            pendingSend[msgId] = { className: className, fields: fields };
          } catch (_) {}
        },
      });
      console.log("[✓] Hooked GameClient.send_msg(id, sdp, no_response)");
    }
  } catch (e) {
    console.warn("[!] Gagal hook send_msg(sdp): " + (e && e.message));
  }

  // 2b. SdpPackerImpl.pack(SdpWrapper val, UInt32 msgId): ambil byte hasil serialisasi
  try {
    const packMethod = image
      .class("MTTDProto.SdpPackerImpl")
      .methods.find(
        (m) =>
          m.name === "pack" &&
          m.parameterCount === 2 &&
          m.parameters[1].type.name === "System.UInt32" &&
          m.parameters[0].type.name === "MTTDProto.SdpWrapper",
      );

    if (packMethod) {
      Interceptor.attach(packMethod.virtualAddress, {
        onEnter(args) {
          this.packer = args[0];
          this.msgId = args[2].toUInt32();
        },
        onLeave() {
          try {
            const arrPtr = this.packer.add(0x20).readPointer(); // m_data (byte[])
            const size = this.packer.add(0x1c).readInt(); // pos
            if (arrPtr.isNull() || size <= 0 || size > MAX_RECV_BYTES) return;

            const dataOffset = Process.pointerSize === 8 ? 0x20 : 0x10;
            const raw = arrPtr.add(dataOffset).readByteArray(size);

            const ctx = pendingSend[this.msgId] || {
              className: "Unknown",
              fields: {},
            };
            delete pendingSend[this.msgId];

            send(
              {
                kind: "packet",
                direction: "SEND",
                opcode: hex(this.msgId),
                opcode_name: OPCODE_NAMES[this.msgId] || "UnknownOpcode",
                class_name: ctx.className,
                timestamp: Date.now(),
                fields: ctx.fields,
              },
              raw,
            );
          } catch (e) {
            console.warn("[!] Error pack onLeave: " + (e && e.message));
          }
        },
      });
      console.log("[✓] Hooked SdpPackerImpl.pack(SdpWrapper, UInt32)");
    } else {
      console.warn(
        "[!] SdpPackerImpl.pack(SdpWrapper, UInt32) tidak ditemukan",
      );
    }
  } catch (e) {
    console.warn("[!] Gagal hook pack: " + (e && e.message));
  }

  // 2c. send_msg(id, byte[] data, iMsgSize, has_req_proto, no_response): byte mentah langsung
  try {
    const sendRaw = image
      .class("GameService.GameClient")
      .methods.find((m) => m.name === "send_msg" && m.parameterCount === 5);

    if (sendRaw) {
      Interceptor.attach(sendRaw.virtualAddress, {
        onEnter(args) {
          try {
            const msgId = args[1].toUInt32();
            const arrPtr = args[2];
            const size = args[3].toInt32();
            if (arrPtr.isNull() || size <= 0 || size > MAX_RECV_BYTES) return;

            const dataOffset = Process.pointerSize === 8 ? 0x20 : 0x10;
            send(
              {
                kind: "packet",
                direction: "SEND",
                opcode: hex(msgId),
                opcode_name: OPCODE_NAMES[msgId] || "UnknownOpcode",
                class_name: "Byte[] / Raw",
                timestamp: Date.now(),
                fields: {},
              },
              arrPtr.add(dataOffset).readByteArray(size),
            );
          } catch (_) {}
        },
      });
      console.log("[✓] Hooked GameClient.send_msg(id, byte[], ...)");
    }
  } catch (e) {
    console.warn("[!] Gagal hook send_msg(byte[]): " + (e && e.message));
  }

  // ---- 3. TAG: MTTDProto.SdpUnpackerImpl.visit ----
  try {
    const visitMethods = image
      .class("MTTDProto.SdpUnpackerImpl")
      .methods.filter((m) => {
        if (m.name !== "visit" || m.parameterCount < 3) return false;
        try {
          return m.parameters[2].type.name === "System.String";
        } catch (_) {
          return false;
        }
      });

    visitMethods.forEach((method) => {
      try {
        Interceptor.attach(method.virtualAddress, {
          onEnter(args) {
            try {
              const tag = args[1].toUInt32();
              const require = args[2].toInt32() !== 0;
              let fieldName = "unknown";
              if (!args[3].isNull()) {
                try {
                  fieldName = new Il2Cpp.String(args[3]).content || "empty";
                } catch (_) {}
              }
              const tid = Process.getCurrentThreadId();
              send({
                kind: "tag",
                direction: "TAG",
                opcode:
                  currentWireOpcode.get(tid) ||
                  currentOpcode.get(tid) ||
                  "visit",
                call_id: currentUnpackCall.get(tid) || null,
                tag: tag,
                field_name: fieldName,
                require: require,
                thread: tid,
                timestamp: Date.now(),
              });
            } catch (_) {}
          },
        });
      } catch (_) {}
    });
    console.log(
      "[✓] Hooked " + visitMethods.length + " overload SdpUnpackerImpl.visit",
    );
  } catch (e) {
    console.warn("[!] Gagal hook visit: " + (e && e.message));
  }

  // ---- 3b. Amplop: opcode wire + body langsung dari RspProto/ReqProto ----
  // Ini sumber paling bersih: iRspCmdId/iReqCmdId adalah opcode WIRE dan
  // sRspData/sReqData adalah body SDP milik pesan itu. Tidak perlu menebak
  // dari waktu atau dari nilai balik Unpack.
  try {
    const envelope = [
      {
        className: "MTTDProto.RspProto",
        argType: "MTTDProto.SdpUnpacker",
        direction: "RECV",
        idOffset: 0x10,
        dataOffset: 0x28,
        codeOffset: 0x20,
      },
      {
        className: "MTTDProto.ReqProto",
        argType: "MTTDProto.SdpPacker",
        direction: "SEND",
        idOffset: 0x10,
        dataOffset: 0x18,
        codeOffset: null,
      },
      // Header selalu ada meski body kosong; dipakai sebagai cadangan opcode.
      {
        className: "MTTDProto.RspProtoHeader",
        argType: "MTTDProto.SdpUnpacker",
        direction: "RECV",
        idOffset: 0x10,
        dataOffset: null,
        codeOffset: null,
      },
      {
        className: "MTTDProto.ReqProtoHeader",
        argType: "MTTDProto.SdpPacker",
        direction: "SEND",
        idOffset: 0x10,
        dataOffset: null,
        codeOffset: null,
      },
    ];

    for (const cfg of envelope) {
      let cls;
      try {
        cls = image.class(cfg.className);
      } catch (_) {
        continue;
      }

      // visit(SdpUnpacker, bool) untuk RspProto, visit(SdpPacker, bool) untuk ReqProto.
      const methods = cls.methods.filter((m) => {
        if (m.name !== "visit" || m.parameterCount !== 2) return false;
        try {
          return m.parameters[0].type.name === cfg.argType;
        } catch (_) {
          return false;
        }
      });
      if (!methods.length) {
        console.warn("[!] " + cfg.className + ".visit tidak ditemukan");
        continue;
      }

      // Info field class sekali, untuk memastikan offset di dump.cs cocok.
      try {
        send({
          kind: "debug",
          where: "env.fields",
          class_name: cfg.className,
          fields: cls.fields.map((f) => f.name + "@0x" + f.offset.toString(16)),
        });
      } catch (_) {}

      methods.forEach((method) => {
        try {
          Interceptor.attach(method.virtualAddress, {
            onEnter(args) {
              this.self = args[0];
            },
            // onLeave: field sudah terisi oleh visit(). Baca setelah selesai.
            onLeave() {
              try {
                if (!isValidPtr(this.self)) return;
                const opcode = this.self.add(cfg.idOffset).readU32();

                // Debug sekali per class: tampilkan nilai mentah walau bukan 0x70.
                const key = "dbgEnv:" + cfg.className;
                if (!globalThis[key]) {
                  globalThis[key] = true;
                  send({
                    kind: "debug",
                    where: "env.sample",
                    class_name: cfg.className,
                    self: this.self.toString(),
                    u10: hex(opcode),
                    u14: this.self.add(0x14).readU32(),
                    u20: hex(this.self.add(0x20).readU32()),
                  });
                }

                if (opcode >>> 24 !== 0x70) return;
                const seq = this.self.add(0x14).readU32();
                const code =
                  cfg.codeOffset === null
                    ? null
                    : this.self.add(cfg.codeOffset).readS32();

                let bodyHex = "";
                if (cfg.dataOffset !== null) {
                  const arrPtr = this.self.add(cfg.dataOffset).readPointer();
                  if (isValidPtr(arrPtr)) {
                    const bodyLen = arrPtr.add(0x18).readS32();
                    if (bodyLen > 0 && bodyLen <= MAX_RECV_BYTES) {
                      const buf = arrPtr
                        .add(Process.pointerSize === 8 ? 0x20 : 0x10)
                        .readByteArray(bodyLen);
                      if (buf)
                        bodyHex = Array.from(new Uint8Array(buf))
                          .map((b) => b.toString(16).padStart(2, "0"))
                          .join("");
                    }
                  }
                }

                send({
                  kind: "wire_body",
                  direction: cfg.direction,
                  opcode: hex(opcode),
                  seq,
                  rsp_code: code,
                  body_hex: bodyHex,
                  body_len: bodyHex.length / 2,
                  thread: Process.getCurrentThreadId(),
                  timestamp: Date.now(),
                });
              } catch (e) {
                const key = "dbgEnvErr:" + cfg.className;
                if (!globalThis[key]) {
                  globalThis[key] = true;
                  send({
                    kind: "debug",
                    where: "env.error",
                    class_name: cfg.className,
                    error: String(e),
                  });
                }
              }
            },
          });
        } catch (_) {}
      });
      console.log(
        "[✓] Hooked " + cfg.className + ".visit (" + methods.length + ")",
      );
    }
  } catch (e) {
    console.warn("[!] Gagal hook RspProto/ReqProto: " + (e && e.message));
  }

  // ---- 3c. Titik emas: bytesToSdp(byte[] s, Type type) ----
  // Fungsi ini menerima BODY dan TYPE target sekaligus, jadi pasangan
  // (class_name, body) bisa diambil tanpa menebak urutan/waktu. Opcode wire
  // dicocokkan offline dari body yang sama pada paket RECV.
  try {
    const hosts = ["MTTDProto.SdpWrapper", "CTools2"];
    let hooked = 0;
    for (const hostName of hosts) {
      let host;
      try {
        host = image.class(hostName);
      } catch (_) {
        continue;
      }
      const methods = host.methods.filter((m) => {
        if (m.name !== "bytesToSdp" && m.name !== "bytesToSdpCached")
          return false;
        try {
          return m.parameters.some((p) => p.type.name === "System.Type");
        } catch (_) {
          return false;
        }
      });

      methods.forEach((method) => {
        try {
          const shift = method.isStatic ? 0 : 1;
          // Cari indeks parameter byte[] dan Type.
          let byteIdx = -1;
          let typeIdx = -1;
          method.parameters.forEach((p, i) => {
            const n = p.type.name;
            if (n === "System.Byte[]") byteIdx = i + shift;
            else if (n === "System.Type") typeIdx = i + shift;
          });
          if (byteIdx < 0 || typeIdx < 0) return;

          Interceptor.attach(method.virtualAddress, {
            onEnter(args) {
              try {
                const typeObj = args[typeIdx];
                if (!typeObj || typeObj.isNull()) return;
                const typePtr = typeObj.add(0x10).readPointer();
                const className = new Il2Cpp.Type(typePtr).class.name;
                if (!className || className.indexOf("Cmd_") !== 0) return;

                const arrPtr = args[byteIdx];
                if (!arrPtr || arrPtr.isNull()) return;
                const len = arrPtr.add(0x18).readS32();
                if (len <= 0 || len > MAX_RECV_BYTES) return;
                const buf = arrPtr
                  .add(Process.pointerSize === 8 ? 0x20 : 0x10)
                  .readByteArray(len);
                if (!buf) return;
                const hexStr = Array.from(new Uint8Array(buf))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");

                send({
                  kind: "sdp_body",
                  direction: "BODY",
                  class_name: className,
                  body_hex: hexStr,
                  body_len: len,
                  thread: Process.getCurrentThreadId(),
                  timestamp: Date.now(),
                });
              } catch (_) {}
            },
          });
          hooked++;
        } catch (_) {}
      });
    }
    console.log("[✓] Hooked " + hooked + " bytesToSdp(byte[], Type)");
  } catch (e) {
    console.warn("[!] Gagal hook bytesToSdp: " + (e && e.message));
  }

  // ---- 4. SdpDisplayer debug ----
  try {
    image.class("MTTDProto.SdpDisplayer").field("m_bPrintSdp").value = true;
    console.log("[★] MTTDProto.SdpDisplayer.m_bPrintSdp = true");
  } catch (e) {
    console.warn("[!] Gagal set m_bPrintSdp: " + (e && e.message));
  }

  // ---- 5. Peta opcode -> class: PackUtil.Unpack(Type, ReturnMsg) ----
  // ReturnMsg.messageid (offset 0x10) berisi opcode penuh, sedangkan nilai balik
  // Unpack adalah objek hasil dekode. Class objek itu = class pesan untuk opcode
  // tersebut, jadi hook ini mengisi tabel FR-2.1 tanpa menebak dari nama file.
  try {
    // Nama lengkapnya NetUtil.PackUtil (lihat DecodeMsgBody di hook #1).
    let packUtil = null;
    for (const name of ["NetUtil.PackUtil", "PackUtil"]) {
      try {
        packUtil = image.class(name);
        break;
      } catch (_) {}
    }
    if (!packUtil) throw new Error("class NetUtil.PackUtil tidak ditemukan");
    packUtilClass = packUtil;
    // Hanya overload utama yang relevan: Unpack(Type, ReturnMsg) dan
    // UnpackCached(Type, ReturnMsg). Overload generik lain memakai T& (ref)
    // sehingga argumennya bukan pointer objek.
    const unpackMethods = packUtil.methods.filter((m) => {
      if (m.name !== "Unpack" && m.name !== "UnpackCached") return false;
      try {
        return (
          m.parameterCount === 2 &&
          m.parameters[0].type.name === "System.Type" &&
          m.parameters[1].type.name === "ReturnMsg"
        );
      } catch (_) {
        return false;
      }
    });
    console.log("[i] overload Unpack utama: " + unpackMethods.length);

    unpackMethods.forEach((method) => {
      try {
        Interceptor.attach(method.virtualAddress, {
          onEnter(args) {
            this.tid = Process.getCurrentThreadId();
            // Kedalaman Unpack per thread: hanya panggilan terluar yang
            // class-nya Cmd_* dan yang diberi call_id untuk tag body.
            const depth = (unpackDepth.get(this.tid) || 0) + 1;
            unpackDepth.set(this.tid, depth);
            this.top = depth === 1;
            if (this.top) {
              this.callId = ++unpackCallSeq;
              currentUnpackCall.set(this.tid, this.callId);
            }

            // Unpack(Type, ReturnMsg) static: args[0]=Type, args[1]=ReturnMsg.
            // Layout ReturnMsg build ini sudah terverifikasi:
            //   +0x0  int32  messageid
            //   +0x4  int32  rspcode
            //   +0x8  uint32 rspseq
            //   +0x10 pointer ke byte[] bt (panjang +0x18, data +0x20 di 64-bit)
            const p = args[1];
            this.msgId = null;
            if (p && !p.isNull()) {
              try {
                const v = p.readU32();
                // messageid internal yang wajar (bukan 0xffffffff/0)
                if (v !== 0 && v !== 0xffffffff) this.msgId = v;
              } catch (_) {}
            }

            // Emit pasangan (class_name, body) untuk setiap panggilan Unpack
            // terluar. Body diambil langsung dari ReturnMsg.bt sebelum di-decode,
            // sehingga bisa dicocokkan byte-per-byte dengan paket RECV offline.
            if (this.top && p && !p.isNull() && args[0] && !args[0].isNull()) {
              try {
                const typePtr = args[0].add(0x10).readPointer();
                const className = new Il2Cpp.Type(typePtr).class.name;
                if (!globalThis.__emitDbg) globalThis.__emitDbg = { ok: 0, err: 0 };
                if (className && className.indexOf("Cmd_") === 0) {
                  const bt = p.add(0x10).readPointer();
                  if (bt && !bt.isNull()) {
                    const len = bt.add(0x18).readS32();
                    if (len > 0 && len <= MAX_RECV_BYTES) {
                      const buf = bt
                        .add(Process.pointerSize === 8 ? 0x20 : 0x10)
                        .readByteArray(len);
                      if (buf) {
                        globalThis.__emitDbg.ok++;
                        if (globalThis.__emitDbg.ok <= 2)
                          send({
                            kind: "debug",
                            where: "emit.ok",
                            class_name: className,
                            body_len: len,
                          });
                        send({
                          kind: "sdp_body",
                          direction: "BODY",
                          class_name: className,
                          body_hex: Array.from(new Uint8Array(buf))
                            .map((b) => b.toString(16).padStart(2, "0"))
                            .join(""),
                          body_len: len,
                          msg_id: this.msgId !== null ? hex(this.msgId) : null,
                          call_id: this.callId || null,
                          thread: this.tid,
                          timestamp: Date.now(),
                        });
                      } else {
                        globalThis.__emitDbg.err++;
                        if (globalThis.__emitDbg.err <= 2)
                          send({ kind: "debug", where: "emit.noBuf", class_name: className, body_len: len });
                      }
                    } else {
                      globalThis.__emitDbg.err++;
                      if (globalThis.__emitDbg.err <= 2)
                        send({ kind: "debug", where: "emit.badLen", class_name: className, body_len: len, bt: bt.toString() });
                    }
                  } else {
                    globalThis.__emitDbg.err++;
                    if (globalThis.__emitDbg.err <= 2)
                      send({ kind: "debug", where: "emit.badBt", class_name: className, bt: bt.toString() });
                  }
                }
              } catch (e) {
                if (!globalThis.__emitDbg) globalThis.__emitDbg = { ok: 0, err: 0 };
                globalThis.__emitDbg.err++;
                if (globalThis.__emitDbg.err <= 3)
                  send({
                    kind: "debug",
                    where: "emit.error",
                    err: String(e),
                    a0: args[0] ? args[0].toString() : "none",
                    a1: args[1] ? args[1].toString() : "none",
                  });
              }
            }

            // Debug sekali: resolusi nama class dari argumen Type (System.Type)
            // dan baca body dari ReturnMsg.bt. Keduanya dipakai untuk memetakan
            // opcode -> class tanpa mengandalkan urutan/waktu.
            if (!globalThis.__dbgType) {
              globalThis.__dbgType = true;
              const info = {
                kind: "debug",
                where: "Unpack.type",
                a0: args[0] ? args[0].toString() : "none",
                a1: args[1] ? args[1].toString() : "none",
              };
              try {
                // System.Type (Il2CppReflectionType): +0x10 = Il2CppType*.
                // Il2Cpp.Type.class.name memberi nama class target.
                const typePtr = args[0].add(0x10).readPointer();
                info.typePtr = typePtr.toString();
                const t = new Il2Cpp.Type(typePtr);
                info.className = t.class.name;
                info.classFullName = t.class.fullName;
              } catch (e) {
                info.typeError = String(e);
              }
              try {
                // Coba dua kemungkinan: args[1] langsung ReturnMsg, atau
                // args[1] menunjuk ke slot yang berisi pointer ReturnMsg.
                const candidates = [args[1]];
                try {
                  const deref = args[1].readPointer();
                  if (deref && !deref.isNull() && !deref.equals(args[1]))
                    candidates.push(deref);
                } catch (_) {}
                // Coba bungkus sebagai objek Il2Cpp: kalau ini benar ReturnMsg,
                // metadata field memberi offset yang benar tanpa menebak.
                try {
                  const obj = new Il2Cpp.Object(args[1]);
                  info.objClass = obj.class.name;
                  info.objFields = obj.class.fields.map(
                    (f) => f.name + "@0x" + f.offset.toString(16),
                  );
                  try {
                    const f = obj.tryField("messageid");
                    info.messageid = f ? String(f.value) : null;
                  } catch (e) {
                    info.messageidErr = String(e);
                  }
                  try {
                    const f = obj.tryField("bt");
                    const arr = f ? f.value : null;
                    info.btClass = arr ? arr.class.name : null;
                    info.btIsNull = arr ? arr.isNull() : null;
                  } catch (e) {
                    info.btErr = String(e);
                  }
                } catch (e) {
                  info.objError = String(e);
                }

                // Hipotesis: args[1] menunjuk struct ReturnMsg versi build ini
                // (messageid di 0, rspcode 4, rspseq 8, bt di 0x10).
                try {
                  const p = args[1];
                  const st = {
                    messageid: p.readS32(),
                    rspcode: p.add(4).readS32(),
                    rspseq: p.add(8).readU32(),
                  };
                  for (const off of [0x10, 0x18, 0x20, 0x30]) {
                    try {
                      const ptr = p.add(off).readPointer();
                      if (!ptr || ptr.isNull()) continue;
                      const len = ptr.add(0x18).readS32();
                      if (len > 0 && len <= 8192) {
                        const b = ptr.add(0x20).readByteArray(Math.min(len, 32));
                        st["off" + off.toString(16)] = {
                          ptr: ptr.toString(),
                          len,
                          hex: b
                            ? Array.from(new Uint8Array(b))
                                .map((x) => x.toString(16).padStart(2, "0"))
                                .join("")
                            : "",
                        };
                      }
                    } catch (_) {}
                  }
                  info.structTry = st;
                } catch (e) {
                  info.structError = String(e);
                }

                try {
                  const buf = args[1].readByteArray(96);
                  if (buf)
                    info.mem96 = Array.from(new Uint8Array(buf))
                      .map((b) => b.toString(16).padStart(2, "0"))
                      .join("");
                } catch (e) {
                  info.memError = String(e);
                }

                info.candidates = candidates.map((p) => p.toString());
                info.reads = candidates.map((p) => {
                  const r = {};
                  try {
                    r.u10 = p.add(0x10).readU32();
                    r.u14 = p.add(0x14).readS32();
                    r.u18 = p.add(0x18).readU32();
                    const bt = p.add(0x20).readPointer();
                    r.bt = bt.toString();
                    const off = Process.pointerSize === 8 ? 0x20 : 0x10;
                    const len = bt.add(0x18).readS32();
                    r.len = len;
                    if (len > 0 && len <= 4096) {
                      const buf = bt.add(off).readByteArray(Math.min(len, 48));
                      if (buf)
                        r.hex = Array.from(new Uint8Array(buf))
                          .map((b) => b.toString(16).padStart(2, "0"))
                          .join("");
                    }
                  } catch (e) {
                    r.error = String(e);
                  }
                  return r;
                });
              } catch (e) {
                info.retError = String(e);
              }
              send(info);
            }

            // Debug sekali untuk memastikan isi ReturnMsg.
            if (!globalThis.__dbgRet) {
              globalThis.__dbgRet = true;
              const info = {
                kind: "debug",
                where: "Unpack.main",
                method: method.name,
                p1: isValidPtr(p) ? p.toString() : "invalid",
                msgId: this.msgId,
              };
              try {
                if (isValidPtr(p)) {
                  info.rspcode = p.add(0x14).readS32();
                  info.rspseq = p.add(0x18).readU32();
                  const bt = p.add(0x20).readPointer();
                  info.bt = isValidPtr(bt) ? bt.toString() : "invalid";
                  if (isValidPtr(bt)) {
                    const off = Process.pointerSize === 8 ? 0x20 : 0x10;
                    const len = bt.add(0x18).readS32();
                    info.btLen = len;
                    const n = Math.min(Math.max(len, 0), 24);
                    if (n > 0) {
                      const buf = bt.add(off).readByteArray(n);
                      if (buf)
                        info.btHex = Array.from(new Uint8Array(buf))
                          .map((b) => b.toString(16).padStart(2, "0"))
                          .join("");
                    }
                  }
                }
              } catch (e) {
                info.error = String(e);
              }
              send(info);
            }
          },
          onLeave(retval) {
            try {
              if (!retval.isNull()) {
                const className = new Il2Cpp.Object(retval).class.name;
                send({
                  kind: "unpack_class",
                  direction: "CLASS",
                  class_name: className,
                  call_id: this.callId || null,
                  msg_id: this.msgId !== null ? hex(this.msgId) : null,
                  thread: this.tid,
                  timestamp: Date.now(),
                });
              }
            } catch (_) {
            } finally {
              // Selalu bersihkan state thread, termasuk saat retval null/error.
              const d = (unpackDepth.get(this.tid) || 1) - 1;
              if (d <= 0) unpackDepth.delete(this.tid);
              else unpackDepth.set(this.tid, d);
              if (this.top) currentUnpackCall.delete(this.tid);
            }
          },
        });
      } catch (_) {}
    });
    console.log("[✓] Hooked " + unpackMethods.length + " PackUtil.Unpack");
  } catch (e) {
    console.warn("[!] Gagal hook PackUtil.Unpack: " + (e && e.message));
  }
}

// ====================================================================
// BOOTSTRAP
// ====================================================================
function runHooks() {
  Il2Cpp.$config.moduleName = TARGET_LIB;
  Il2Cpp.perform(executeSimpleHooks);
}

function setupIl2CppHook(targetMod) {
  const initPtr = findExport(targetMod, "il2cpp_init");
  const domainGetPtr = findExport(targetMod, "il2cpp_domain_get");

  if (!initPtr) {
    console.log("[!] il2cpp_init tidak ditemukan di " + targetMod.name);
    return;
  }

  let initialized = false;
  if (domainGetPtr) {
    try {
      initialized = !new NativeFunction(domainGetPtr, "pointer", [])().isNull();
    } catch (_) {}
  }

  if (initialized) {
    console.log("[+] " + targetMod.name + " sudah terinisialisasi.");
    setTimeout(runHooks, 100);
  } else {
    Interceptor.attach(initPtr, {
      onLeave() {
        console.log("[+] il2cpp_init selesai.");
        runHooks();
      },
    });
  }
}

function waitForLogicLib() {
  console.log("[*] Menunggu " + TARGET_LIB + "...");

  const mod = Process.findModuleByName(TARGET_LIB);
  if (mod) {
    setupIl2CppHook(mod);
    return;
  }

  const dlopen =
    findGlobalExport("android_dlopen_ext") || findGlobalExport("dlopen");

  if (!dlopen) {
    setTimeout(waitForLogicLib, 100);
    return;
  }

  const monitor = Interceptor.attach(dlopen, {
    onEnter(args) {
      try {
        this.path = args[0].readUtf8String();
      } catch (_) {
        this.path = null;
      }
    },
    onLeave() {
      if (this.path && this.path.indexOf(TARGET_LIB) !== -1) {
        monitor.detach();
        setupIl2CppHook(Process.getModuleByName(TARGET_LIB));
      }
    },
  });
}

function main() {
  console.log("[*] Menunggu EGL rendering siap...");

  const libEGL =
    Process.findModuleByName("libEGL.so") ||
    Process.findModuleByName("libGLESv2.so");
  let swap = null;
  if (libEGL) swap = findExport(libEGL, "eglSwapBuffers");
  if (!swap) swap = findGlobalExport("eglSwapBuffers");

  if (!swap) {
    setTimeout(main, 50);
    return;
  }

  let frames = 0;
  const h = Interceptor.attach(swap, {
    onEnter() {
      if (++frames >= 2) {
        h.detach();
        console.log("[+] EGL siap.");
        waitForLogicLib();
      }
    },
  });
}

main();

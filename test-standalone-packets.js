const assert = require("assert");
const sdp = require("./sdp");
const auth = require("./auth-server");

console.log("=== Running Standalone Packet Round-Trip and Builder Tests ===");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`PASS  ${name}`);
    passed++;
  } catch (err) {
    console.error(`FAIL  ${name}: ${err.message}`);
    failed++;
  }
}

// 1. Cmd_Login_Echo_SC (0x70000e01)
test("Cmd_Login_Echo_SC (0x70000e01) round-trip", () => {
  const pkt = auth.buildLoginEchoSC(1);
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x70000e01);
  assert.strictEqual(parsed.seq, 1);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

// 2. Cmd_Login_GetLangAndCodeRepair_SC (0x7000be4e)
test("Cmd_Login_GetLangAndCodeRepair_SC (0x7000be4e) round-trip", () => {
  const pkt = auth.buildLoginGetLangAndCodeRepairSC(2, {
    vServerDataStr: [{ iKey: 1, sVal: "repair_data" }],
    vServerDataStrDel: [101, 102],
    iServerDataStrTimestamp: 1700000000,
    mLuaCodeFromServer: { "main.lua": "print('ok')" },
    stLuaCodeFromServerIncrUpdate: {},
  });
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x7000be4e);
  assert.strictEqual(parsed.seq, 2);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

// 3. Cmd_Act_GetListByStage_SC (0x7000c8ea)
test("Cmd_Act_GetListByStage_SC (0x7000c8ea) round-trip", () => {
  const pkt = auth.buildActGetListByStageSC(3, {
    iStageId: 1,
    vActivity: [
      { iActivityId: 2001, sName: "Carnival", iType: 2, iStartTime: 1000, iEndTime: 2000 },
    ],
    iLastLanguageId: 1,
    iClientActivityVersion: 5,
    vBriefActivity: [{ iActivityId: 2001, iStatus: 1 }],
    vBriefActivityIdList: [2001],
    vActivityDiffData: [{ iActivityId: 2001 }],
    iPageCur: 1,
    iPageMax: 1,
    sMd5PageCur: "abcdef123456",
  });
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x7000c8ea);
  assert.strictEqual(parsed.seq, 3);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

// 4. Cmd_Act_GetStatusById_SC (0x7000b4ea)
test("Cmd_Act_GetStatusById_SC (0x7000b4ea) round-trip", () => {
  const pkt = auth.buildActGetStatusByIdSC(4, {
    vStatus: [
      { iActivityId: 2001, iStatus: 1, iConditionVal: 10, bFinished: true },
    ],
  });
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x7000b4ea);
  assert.strictEqual(parsed.seq, 4);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

// 5. Cmd_Act_CityPing_GetPing_SC (0x7000f9ff)
test("Cmd_Act_CityPing_GetPing_SC (0x7000f9ff) round-trip", () => {
  const pkt = auth.buildActCityPingGetPingSC(5, {
    iActivityId: 3001,
    vecPing: [{ iCityId: 62, iPing: 28 }],
  });
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x7000f9ff);
  assert.strictEqual(parsed.seq, 5);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

// 6. Cmd_Act_ThreadBind_getThreadBindData_SC (0x7000cb94)
test("Cmd_Act_ThreadBind_getThreadBindData_SC (0x7000cb94) round-trip", () => {
  const pkt = auth.buildActThreadBindGetThreadBindDataSC(6, {
    iActivityId: 4001,
    vThreadBind: [{ iThreadId: 10, sUrl: "https://community.mlbb.com" }],
  });
  const parsed = sdp.parseFrame(pkt);
  assert.strictEqual(parsed.opcode, 0x7000cb94);
  assert.strictEqual(parsed.seq, 6);
  const decoded = sdp.decode(parsed.body);
  const reencoded = sdp.encode(decoded);
  assert(reencoded.equals(parsed.body), "Body SDP harus round-trip identik");
});

console.log(`\nResults: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
}

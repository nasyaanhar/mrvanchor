// Deterministic scenario evaluation: each scenario executed once on MRVAnchor (v2) and on the hash-bound baseline.
const fs = require("fs");
const { rnd32, TYPES_APPROVAL, TYPES_REJECTION, TYPES_HASH, errName, now, setup, ethers } = require("./lib");

async function main() {
  const { signers, admin, V2, BL, dV2, dBL } = await setup();
  let opIdx = 1;
  const gas = {}; const g = (k, r) => (gas[k] ||= []).push(Number(r.gasUsed));
  async function tx(label, p) {
    try { const r = await (await p).wait(); if (label) g(label, r); return "ANCHORED_OR_OK"; }
    catch (e) { return errName(e); }
  }

  // fixture: plant with operator, validator assigned on v2 and authorized on baseline, record v1 registered
  async function fixture() {
    const op = signers[opIdx++ % 15 + 1];
    const plantId = rnd32(), recordId = rnd32(), dataHash = rnd32(), period = 202500 + Math.floor(Math.random() * 99);
    const val = ethers.Wallet.createRandom();
    g("setPlantOperator", await (await V2.connect(admin).setPlantOperator(plantId, op.address)).wait());
    g("assignValidator", await (await V2.connect(admin).assignValidator(plantId, val.address, true)).wait());
    g("baseline.setValidator", await (await BL.connect(admin).setValidator(val.address, true)).wait());
    g("registerRecordVersion(v1)", await (await V2.connect(op).registerRecordVersion(recordId, 1, plantId, period, dataHash)).wait());
    const deadline = (await now()) + 3600;
    const a = { recordId, version: 1, plantId, reportingPeriod: period, dataHash, validator: val.address, deadline };
    return { op, val, plantId, recordId, dataHash, period, a };
  }
  const signV2 = (w, a) => w.signTypedData(dV2, TYPES_APPROVAL, a);
  const signBL = (w, h, v) => w.signTypedData(dBL, TYPES_HASH, { dataHash: h, validator: v });
  const relayer = signers[18];

  const S = [];
  const add = (id, cond, expV2, fnV2, fnBL) => S.push({ id, cond, expV2, fnV2, fnBL });

  add("S1", "Valid approval submitted by operator", "ANCHORED", async () => {
    const f = await fixture(); return tx("anchorRecord", V2.connect(f.op).anchorRecord(f.a, await signV2(f.val, f.a)));
  }, async () => {
    const f = await fixture(); return tx("baseline.anchorRecord", BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address)));
  });
  add("S2", "Operator withholds; validator-side relayer submits", "ANCHORED", async () => {
    const f = await fixture(); return tx(null, V2.connect(relayer).anchorRecord(f.a, await signV2(f.val, f.a)));
  }, async () => {
    const f = await fixture(); return tx(null, BL.connect(relayer).anchorRecord(f.recordId, f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address)));
  });
  add("S3", "Signer is a validator assigned to another plant", "VALIDATOR_NOT_ASSIGNED", async () => {
    const f = await fixture(); const g2 = await fixture();              // g2.val assigned only to plant of g2
    const a = { ...f.a, validator: g2.val.address };
    return tx(null, V2.connect(f.op).anchorRecord(a, await signV2(g2.val, a)));
  }, async () => {
    const f = await fixture(); const g2 = await fixture();
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, g2.val.address, await signBL(g2.val, f.dataHash, g2.val.address)));
  });
  add("S4", "Operator also holds a validator role and self-approves", "SELF_APPROVAL_NOT_ALLOWED", async () => {
    const f = await fixture(); await (await V2.connect(admin).assignValidator(f.plantId, f.op.address, true)).wait();
    const a = { ...f.a, validator: f.op.address };
    const r = await tx(null, V2.connect(f.op).anchorRecord(a, await signV2(f.op, a)));
    await (await V2.connect(admin).assignValidator(f.plantId, f.op.address, false)).wait(); return r;
  }, async () => {
    const f = await fixture(); await (await BL.connect(admin).setValidator(f.op.address, true)).wait();
    const r = await tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.op.address, await signBL(f.op, f.dataHash, f.op.address)));
    await (await BL.connect(admin).setValidator(f.op.address, false)).wait(); return r;
  });
  add("S5", "Record identifier never registered", "RECORD_NOT_REGISTERED", async () => {
    const f = await fixture(); const a = { ...f.a, recordId: rnd32() };
    return tx(null, V2.connect(f.op).anchorRecord(a, await signV2(f.val, a)));
  }, async () => {
    const f = await fixture(); return tx(null, BL.connect(f.op).anchorRecord(rnd32(), f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address)));
  });
  add("S6", "Validator approved data that differ from the registered hash", "DATA_HASH_MISMATCH", async () => {
    const f = await fixture(); const a = { ...f.a, dataHash: rnd32() };   // reviewed copy ≠ registered copy
    return tx(null, V2.connect(f.op).anchorRecord(a, await signV2(f.val, a)));
  }, async () => {
    const f = await fixture(); const h = rnd32();                          // baseline has no registered hash to compare
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, h, f.val.address, await signBL(f.val, h, f.val.address)));
  });
  add("S7", "Signed field altered after signing", "INVALID_APPROVAL_SIGNATURE", async () => {
    const f = await fixture(); const sig = await signV2(f.val, f.a);
    return tx(null, V2.connect(f.op).anchorRecord({ ...f.a, deadline: f.a.deadline + 86400 }, sig));   // deadline extended
  }, async () => {
    const f = await fixture(); const sig = await signBL(f.val, f.dataHash, f.val.address);
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, rnd32(), f.val.address, sig));         // hash replaced
  });
  add("S8", "Approval for v1 submitted after v2 correction", "STALE_VERSION", async () => {
    const f = await fixture(); const sig = await signV2(f.val, f.a);
    g("registerRecordVersion(correction)", await (await V2.connect(f.op).registerRecordVersion(f.recordId, 2, f.plantId, f.period, rnd32())).wait());
    return tx(null, V2.connect(f.op).anchorRecord(f.a, sig));
  }, async () => {
    const f = await fixture(); const sig = await signBL(f.val, f.dataHash, f.val.address);   // corrected data exist off-chain only
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, sig));
  });
  add("S9", "Approval of record A reused for record B (same plant, other period, other data)", "INVALID_APPROVAL_SIGNATURE", async () => {
    const f = await fixture(); const sig = await signV2(f.val, f.a);
    const recB = rnd32(), hB = rnd32(), perB = f.period + 1;
    await (await V2.connect(f.op).registerRecordVersion(recB, 1, f.plantId, perB, hB)).wait();
    return tx(null, V2.connect(f.op).anchorRecord({ ...f.a, recordId: recB, reportingPeriod: perB, dataHash: hB }, sig));
  }, async () => {
    const f = await fixture(); const sig = await signBL(f.val, f.dataHash, f.val.address);
    return tx(null, BL.connect(f.op).anchorRecord(rnd32(), f.dataHash, f.val.address, sig));    // record B anchored with A's approval
  });
  add("S10", "Approval declares a plant or period other than the registered one", "RECORD_CONTEXT_MISMATCH", async () => {
    const f = await fixture(); const a = { ...f.a, reportingPeriod: f.period + 7 };
    return tx(null, V2.connect(f.op).anchorRecord(a, await signV2(f.val, a)));
  }, async () => {
    const f = await fixture();   // baseline carries no plant/period: same call as a valid one
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address)));
  });
  add("S11", "Approval submitted after its deadline", "APPROVAL_EXPIRED", async () => {
    const f = await fixture(); const a = { ...f.a, deadline: (await now()) + 60 }; const sig = await signV2(f.val, a);
    await ethers.provider.send("evm_increaseTime", [3600]); await ethers.provider.send("evm_mine", []);
    return tx(null, V2.connect(f.op).anchorRecord(a, sig));
  }, async () => {
    const f = await fixture(); const sig = await signBL(f.val, f.dataHash, f.val.address);
    await ethers.provider.send("evm_increaseTime", [3600]); await ethers.provider.send("evm_mine", []);
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, sig));
  });
  add("S12", "Version rejected on-chain, then an approval is submitted for it", "RECORD_REJECTED", async () => {
    const f = await fixture(); const reason = rnd32();
    const rsig = await f.val.signTypedData(dV2, TYPES_REJECTION, { ...f.a, reasonHash: reason });
    const rr = await tx("recordRejection", V2.connect(relayer).recordRejection(f.a, reason, rsig));
    if (rr !== "ANCHORED_OR_OK") return "REJECTION_FAILED:" + rr;
    return tx(null, V2.connect(f.op).anchorRecord(f.a, await signV2(f.val, f.a)));
  }, async () => {
    const f = await fixture();   // baseline keeps no rejection trail
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address)));
  });
  add("S13", "Already anchored record submitted again", "ALREADY_ANCHORED", async () => {
    const f = await fixture(); const sig = await signV2(f.val, f.a);
    await (await V2.connect(f.op).anchorRecord(f.a, sig)).wait();
    return tx(null, V2.connect(f.op).anchorRecord(f.a, sig));
  }, async () => {
    const f = await fixture(); const sig = await signBL(f.val, f.dataHash, f.val.address);
    await (await BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, sig)).wait();
    return tx(null, BL.connect(f.op).anchorRecord(f.recordId, f.dataHash, f.val.address, sig));
  });

  const rows = [];
  for (const s of S) {
    const ov = await s.fnV2(); const ob = await s.fnBL();
    const v2 = ov === "ANCHORED_OR_OK" ? "ANCHORED" : ov;
    const bl = ob === "ANCHORED_OR_OK" ? "ANCHORED" : ob;
    const ok = v2 === s.expV2;
    rows.push({ id: s.id, condition: s.cond, expected: s.expV2, mrvanchor: v2, pass: ok, baseline: bl });
    console.log(`${s.id.padEnd(4)} ${ok ? "PASS" : "FAIL"}  v2=${v2.padEnd(27)} baseline=${bl}`);
  }

  // gas: repeat valid flows 20x for stable means
  for (let i = 0; i < 20; i++) {
    const f = await fixture();
    g("anchorRecord", await (await V2.connect(f.op).anchorRecord(f.a, await signV2(f.val, f.a))).wait());
    g("baseline.anchorRecord", await (await BL.connect(f.op).anchorRecord(rnd32(), f.dataHash, f.val.address, await signBL(f.val, f.dataHash, f.val.address))).wait());
    const f2 = await fixture(); const reason = rnd32();
    g("recordRejection", await (await V2.connect(relayer).recordRejection(f2.a, reason, await f2.val.signTypedData(dV2, TYPES_REJECTION, { ...f2.a, reasonHash: reason }))).wait());
    g("registerRecordVersion(correction)", await (await V2.connect(f2.op).registerRecordVersion(f2.recordId, 2, f2.plantId, f2.period, rnd32())).wait());
  }
  const f = await fixture(); await (await V2.connect(f.op).anchorRecord(f.a, await signV2(f.val, f.a))).wait();
  const verifyOk = await V2.verifyRecord(f.recordId, f.dataHash), verifyBad = await V2.verifyRecord(f.recordId, rnd32());
  const mean = xs => Math.round(xs.reduce((s, x) => s + x, 0) / xs.length);
  const gasSummary = Object.fromEntries(Object.entries(gas).map(([k, v]) => [k, { n: v.length, mean: mean(v), min: Math.min(...v), max: Math.max(...v) }]));
  console.log(gasSummary, { verifyOk, verifyBad, verifyGas: Number(await V2.verifyRecord.estimateGas(f.recordId, f.dataHash)) });

  fs.writeFileSync("results/scenarios.csv", "id,condition,expected_mrvanchor,observed_mrvanchor,pass,observed_baseline\n" +
    rows.map(r => [r.id, `"${r.condition}"`, r.expected, r.mrvanchor, r.pass, r.baseline].join(",")).join("\n") + "\n");
  fs.writeFileSync("results/summary.json", JSON.stringify({ scenarios: rows, gas: gasSummary, verify: { verifyOk, verifyBad } }, null, 2));
}
main().catch(e => { console.error(e); process.exit(1); });

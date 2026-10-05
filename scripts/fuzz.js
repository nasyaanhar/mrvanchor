// Model-based differential fuzzing: random combinations of mutations are applied to an approval;
// the contract outcome is compared with an independent reference model of the ten ordered checks.
const fs = require("fs");
const { rnd32, TYPES_APPROVAL, TYPES_REJECTION, errName, now, setup, ethers } = require("./lib");
const N = parseInt(process.env.FUZZ_N || "5000", 10);
const pick = a => a[Math.floor(Math.random() * a.length)];
const flip = p => Math.random() < p;

async function main() {
  const { signers, admin, V2, dV2 } = await setup();
  const relayer = signers[18];
  // a second plant with its own validator (used for "assigned elsewhere" signers)
  const otherPlant = rnd32(); const otherVal = ethers.Wallet.createRandom();
  await (await V2.connect(admin).setPlantOperator(otherPlant, signers[17].address)).wait();
  await (await V2.connect(admin).assignValidator(otherPlant, otherVal.address, true)).wait();

  const counts = {}; let mismatches = 0, invariantViolations = 0, falseAccepts = 0, falseRejects = 0;
  const log = [];
  for (let i = 0; i < N; i++) {
    const op = signers[1 + (i % 15)];
    const plantId = rnd32(), recordId = rnd32(), h1 = rnd32(), period = 202000 + (i % 900);
    const val = ethers.Wallet.createRandom();
    await (await V2.connect(admin).setPlantOperator(plantId, op.address)).wait();
    await (await V2.connect(admin).assignValidator(plantId, val.address, true)).wait();
    await (await V2.connect(op).registerRecordVersion(recordId, 1, plantId, period, h1)).wait();
    const t0 = await now();

    // ---- choose mutations ----
    const m = {
      unreg: flip(0.12), plant: flip(0.12), period: flip(0.12), hash: flip(0.12), expired: flip(0.12),
      tamper: flip(0.12), anchored: flip(0.12),
      signer: pick(["assigned", "assigned", "assigned", "otherPlant", "self", "randomKey", "forged"]),
    };
    m.stale = !m.anchored && flip(0.12);
    m.rejected = !m.anchored && flip(0.12);

    const a = { recordId, version: 1, plantId, reportingPeriod: period, dataHash: h1, validator: val.address,
                deadline: m.expired ? t0 - 100 : t0 + 3600 };
    let signerWallet = val;
    if (m.signer === "otherPlant") { signerWallet = otherVal; a.validator = otherVal.address; }
    if (m.signer === "self") { await (await V2.connect(admin).assignValidator(plantId, op.address, true)).wait(); signerWallet = op; a.validator = op.address; }
    if (m.signer === "randomKey") { signerWallet = ethers.Wallet.createRandom(); a.validator = signerWallet.address; }
    if (m.signer === "forged") { signerWallet = ethers.Wallet.createRandom(); }          // declares assigned validator, signs with another key
    if (m.hash) a.dataHash = rnd32();
    if (m.plant) a.plantId = rnd32();
    if (m.period) a.reportingPeriod = period + 1 + (i % 5);

    // pre-steps on the honest record (performed before the attack)
    const honest = { recordId, version: 1, plantId, reportingPeriod: period, dataHash: h1, validator: val.address, deadline: t0 + 3600 };
    if (m.rejected) {
      const reason = rnd32();
      await (await V2.connect(relayer).recordRejection(honest, reason, await val.signTypedData(dV2, TYPES_REJECTION, { ...honest, reasonHash: reason }))).wait();
    }
    if (m.anchored) await (await V2.connect(relayer).anchorRecord(honest, await val.signTypedData(dV2, TYPES_APPROVAL, honest))).wait();
    if (m.stale) await (await V2.connect(op).registerRecordVersion(recordId, 2, plantId, period, rnd32())).wait();

    let sig = await signerWallet.signTypedData(dV2, TYPES_APPROVAL, a);
    const submitted = { ...a };
    if (m.unreg) submitted.recordId = rnd32();                     // applied after signing: also breaks the signature
    if (m.tamper) submitted.deadline = a.deadline + 1;

    // ---- reference model: first failing check in the specified order ----
    const regHash = submitted.recordId === recordId ? (submitted.version === 1 ? h1 : null) : null;
    const curVersion = m.stale ? 2 : 1;
    const sigValid = !m.unreg && !m.tamper && m.signer !== "forged";
    const recovered = sigValid ? a.validator : null;
    let expected;
    if (!regHash) expected = "RECORD_NOT_REGISTERED";
    else if (m.anchored) expected = "ALREADY_ANCHORED";
    else if (submitted.version !== curVersion) expected = "STALE_VERSION";
    else if (submitted.plantId !== plantId || submitted.reportingPeriod !== period) expected = "RECORD_CONTEXT_MISMATCH";
    else if (submitted.dataHash !== regHash) expected = "DATA_HASH_MISMATCH";
    else if ((await now()) + 1 > submitted.deadline) expected = "APPROVAL_EXPIRED";
    else if (m.rejected) expected = "RECORD_REJECTED";
    else if (!recovered) expected = "INVALID_APPROVAL_SIGNATURE";
    else if (!(m.signer === "assigned" || m.signer === "self")) expected = "VALIDATOR_NOT_ASSIGNED";
    else if (m.signer === "self") expected = "SELF_APPROVAL_NOT_ALLOWED";
    else expected = "ANCHORED";

    let observed;
    try { await (await V2.connect(relayer).anchorRecord(submitted, sig)).wait(); observed = "ANCHORED"; }
    catch (e) { observed = errName(e); }
    if (m.signer === "self") await (await V2.connect(admin).assignValidator(plantId, op.address, false)).wait();

    // ---- invariants ----
    if (await V2.anchored(recordId)) {
      const v = await V2.anchoredVersion(recordId);
      const okInv = (await V2.anchoredDataHash(recordId)) === (await V2.registeredHash(recordId, v)) && v === (await V2.currentVersion(recordId));
      if (!okInv) invariantViolations++;
    }
    if (observed !== expected) {
      mismatches++;
      if (observed === "ANCHORED") falseAccepts++; else if (expected === "ANCHORED") falseRejects++;
      log.push({ i, m, expected, observed });
    }
    counts[expected] = (counts[expected] || 0) + 1;
    if ((i + 1) % 500 === 0) console.log(`${i + 1}/${N} cases, mismatches=${mismatches}`);
  }
  const out = { cases: N, mismatches, falseAccepts, falseRejects, invariantViolations, outcomeDistribution: counts, mismatchLog: log.slice(0, 20) };
  console.log(JSON.stringify(out, null, 2));
  fs.writeFileSync("results/fuzz.json", JSON.stringify(out, null, 2));
}
main().catch(e => { console.error(e); process.exit(1); });

const { ethers } = require("hardhat");
const rnd32 = () => ethers.hexlify(ethers.randomBytes(32));
const TYPES_APPROVAL = { MRVApproval: [
  { name: "recordId", type: "bytes32" }, { name: "version", type: "uint32" },
  { name: "plantId", type: "bytes32" }, { name: "reportingPeriod", type: "uint32" },
  { name: "dataHash", type: "bytes32" }, { name: "validator", type: "address" },
  { name: "deadline", type: "uint64" } ] };
const TYPES_REJECTION = { MRVRejection: [...TYPES_APPROVAL.MRVApproval, { name: "reasonHash", type: "bytes32" }] };
const TYPES_HASH = { HashApproval: [ { name: "dataHash", type: "bytes32" }, { name: "validator", type: "address" } ] };

function errName(e) {
  const m = (e.message || "").match(/custom error '([A-Z_]+)\(/) || (e.message || "").match(/reverted with custom error '([A-Z_]+)/);
  return m ? m[1] : "UNKNOWN_REVERT: " + (e.shortMessage || e.message).slice(0, 80);
}
async function now() { return (await ethers.provider.getBlock("latest")).timestamp; }

async function setup() {
  const signers = await ethers.getSigners();
  const admin = signers[0];
  const { chainId } = await ethers.provider.getNetwork();
  const V2 = await (await ethers.getContractFactory("MRVAnchor")).deploy();
  const BL = await (await ethers.getContractFactory("HashBoundBaseline")).deploy();
  await V2.waitForDeployment(); await BL.waitForDeployment();
  const dV2 = { name: "MRVAnchor", version: "2", chainId, verifyingContract: await V2.getAddress() };
  const dBL = { name: "HashBoundBaseline", version: "1", chainId, verifyingContract: await BL.getAddress() };
  return { signers, admin, V2, BL, dV2, dBL };
}
module.exports = { rnd32, TYPES_APPROVAL, TYPES_REJECTION, TYPES_HASH, errName, now, setup, ethers };

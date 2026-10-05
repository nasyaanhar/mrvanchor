# MRVAnchor — Approval-Bound Anchoring for Carbon MRV

Smart-contract prototype and evaluation scripts for the paper
"Approval-Bound Anchoring: Smart Contract Enforcement of Validator-Approved Carbon MRV Records".

## Contents
- `contracts/MRVAnchor.sol` — proposed contract (EIP-712 approval bound to record id, version, plant, period, data hash, deadline; ten ordered checks; on-chain rejection).
- `contracts/HashBoundBaseline.sol` — comparison baseline (validator signs the data hash only).
- `scripts/run-scenarios.js` — 13 deterministic scenarios on both contracts + gas measurement → `results/scenarios.csv`, `results/summary.json`.
- `scripts/fuzz.js` — model-based differential fuzzing (default 5,000 cases) → `results/fuzz.json`.
- `results/slither.json` — Slither 0.11.6 static-analysis output.

## Reproduce
```bash
npm install
npx hardhat compile
npx hardhat run scripts/run-scenarios.js
FUZZ_N=5000 npx hardhat run scripts/fuzz.js
slither . --hardhat-ignore-compile --filter-paths node_modules
```
Environment: Solidity 0.8.24, Hardhat 2.29.1, OpenZeppelin Contracts 5.1.0, ethers 6.17.0, Node.js 22.

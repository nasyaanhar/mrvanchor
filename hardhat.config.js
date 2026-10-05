require("@nomicfoundation/hardhat-ethers");
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");
const path = require("path");
// Use the solc-js compiler from npm (the binary download host is not reachable in this sandbox).
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (args.solcVersion === "0.8.24") {
    return { compilerPath: path.join(__dirname, "node_modules", "solc", "soljson.js"), isSolcJs: true,
             version: args.solcVersion, longVersion: require("solc/package.json").version };
  }
  return runSuper();
});
module.exports = { solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } } };

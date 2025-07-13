const { ethers} = require("ethers");

// 1. Connect to your local chain or testnet
const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");

// 2. Replace with the deployed Locker address
const lockerAddress = "0x294fA39BAD8A42cC98e13E5812F34beA5fCA9aaf";

// 3. ABI containing only the SignatureUsed event
const abi = [
  "event SignatureUsed(uint8[] v, bytes32[] r, bytes32[] s)",
  "event LockerDeployed(address lockerAddress, uint256 lockId, uint8[] v, bytes32[] r, bytes32[] s, address[] controllers, uint256 threshold)"
];

// 4. Create contract instance
const contract = new ethers.Contract(lockerAddress, abi, provider);

// 5. Query for the event
async function fetchSignature() {
  const logs = await contract.queryFilter("SignatureUsed", 0, "latest");

  for (const log of logs) {
    const { v, r, s } = log.args;
    console.log("Signatures used:");
    for (let i = 0; i < v.length; i++) {
      console.log(`v: ${v[i]}, r: ${r[i]}, s: ${s[i]}`);
    }
  }
}

fetchSignature().catch(console.error);

// 5. Query for the event
async function fetchSignature2() {
  const logs = await contract.queryFilter("LockerDeployed", 0, "latest");

  for (const log of logs) {
    const { v, r, s } = log.args;
    console.log("Signatures used:");
    for (let i = 0; i < v.length; i++) {
      console.log(`v: ${v[i]}, r: ${r[i]}, s: ${s[i]}`);
    }
  }
}

fetchSignature2().catch(console.error);
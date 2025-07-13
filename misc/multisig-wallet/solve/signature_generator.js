const { ethers } = require("ethers");

// === CONFIGURATION ===
const lockId = 0;
const controllerPrivateKeys = [
  "0x047d06f006cd883106f0b67cc3d1f682a191fdedbec5171104bb0b0533aa8906",
  "0x1308a259d7eda262b2c35095eaf377e57dd0b428b69685cff479a76c896364af",
  "0x5eb1c66a60def0e552c6d0b22845e3e5de6498fe906e24d08bc57d26f178f005"
];

// === STEP 1: Generate the message hash ===
function getMessageHash(lockId) {
  const prefix = Buffer.from("\x19Ethereum Signed Message:\n32", "utf-8");
  const paddedLockId = ethers.utils.hexZeroPad(ethers.utils.hexlify(lockId), 32);
  const message = Buffer.concat([prefix, Buffer.from(paddedLockId.slice(2), "hex")]);
  return ethers.utils.keccak256(message);
}

// === STEP 2: Sign and extract (v, r, s) ===
async function generateSignatures(lockId) {
  const msgHash = getMessageHash(lockId);
  console.log("msgHash:", msgHash);

  const signatures = [];
  const controllers = [];

  for (let pk of controllerPrivateKeys) {
    const wallet = new ethers.Wallet(pk);
    controllers.push(wallet.address);

    const rawMessage = ethers.utils.hexZeroPad(ethers.utils.hexlify(lockId), 32);
    const sig = await wallet.signMessage(ethers.utils.arrayify(rawMessage));
    const split = ethers.utils.splitSignature(sig);

    signatures.push({
      v: split.v,
      r: split.r,
      s: split.s,
    });
  }

  console.log("\nSignatures:\n", JSON.stringify(signatures, null, 2));
  console.log("\nController addresses:\n", JSON.stringify(controllers, null, 2));
}

generateSignatures(lockId);

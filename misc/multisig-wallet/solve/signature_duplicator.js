const { ethers } = require("ethers");

// secp256k1 curve order
const N = ethers.BigNumber.from("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

/**
 * Returns the complementary ECDSA signature.
 * 
 * @param {number} v - The recovery id (27 or 28)
 * @param {string} r - The 32-byte r component (hex string)
 * @param {string} s - The 32-byte s component (hex string)
 * @returns {{ v: number, r: string, s: string, remix: [number, string, string] }} - Complementary signature with Remix format
 */
function getComplementarySignature(v, r, s) {
  if (v !== 27 && v !== 28) {
    throw new Error("v must be 27 or 28");
  }

  const sBN = ethers.BigNumber.from(s);
  const sComplement = N.sub(sBN);
  const vComplement = v === 27 ? 28 : 27;
  const sFormatted = ethers.utils.hexZeroPad(sComplement.toHexString(), 32);

  return {
    v: vComplement,
    r,
    s: sFormatted,
    remix: [vComplement, r, sFormatted]
  };
}

const inputSignatures = [
  {
    v: 27,
    r: "0x36ade3c84a9768d762f611fbba09f0f678c55cd73a734b330a9602b7426b18d9",
    s: "0x6f326347e65ae8b25830beee7f3a4374f535a8f6eedb5221efba0f17eceea9a9"
  },
  {
    v: 28,
    r: "0x57f4f9e4f2ef7280c23b31c0360384113bc7aa130073c43bb8ff83d4804bd2a7",
    s: "0x694430205a6b625cc8506e945208ad32bec94583bf4ec116598708f3b65e4910"
  },
  {
    v: 27,
    r: "0xe2e9d4367932529bf0c5c814942d2ff9ae3b5270a240be64b89f839cd4c78d5d",
    s: "0x6c0c845b7a88f5a2396d7f75b536ad577bbdb27ea8c03769a958b2a9d67117d2"
  }
];

const complementarySignatures = inputSignatures.map(sig =>
  getComplementarySignature(sig.v, sig.r, sig.s)
);

complementarySignatures.forEach((sig, index) => {
  console.log(`Complementary Signature ${index + 1}:`);
  console.log(sig);
  console.log();
});

console.log("Remix Input Format:");
console.log("[");
complementarySignatures.forEach((sig, index) => {
  const line = `  [${sig.remix.map(JSON.stringify).join(", ")}]${index < complementarySignatures.length - 1 ? "," : ""}`;
  console.log(line);
});
console.log("]");

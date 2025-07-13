(async () => {
  const contractAddress = "0x294fA39BAD8A42cC98e13E5812F34beA5fCA9aaf";

  const abi = [
    {
      anonymous: false,
      inputs: [
        { indexed: false, internalType: "address", name: "lockerAddress", type: "address" },
        { indexed: false, internalType: "uint256", name: "lockId", type: "uint256" },
        { indexed: false, internalType: "uint8[]", name: "v", type: "uint8[]" },
        { indexed: false, internalType: "bytes32[]", name: "r", type: "bytes32[]" },
        { indexed: false, internalType: "bytes32[]", name: "s", type: "bytes32[]" },
        { indexed: false, internalType: "address[]", name: "controllers", type: "address[]" },
        { indexed: false, internalType: "uint256", name: "threshold", type: "uint256" }
      ],
      name: "LockerDeployed",
      type: "event"
    }
  ];

  const contract = new web3.eth.Contract(abi, contractAddress);

  const events = await contract.getPastEvents("LockerDeployed", { fromBlock: 0, toBlock: "latest" });

  for (const evt of events) {
    const { lockerAddress, lockId, v, r, s, controllers, threshold } = evt.returnValues;

    console.log("🔐 Locker Deployed:");
    console.log(`- Locker Address: ${lockerAddress}`);
    console.log(`- Lock ID       : ${lockId}`);
    console.log(`- Threshold     : ${threshold}`);

    console.log(`- Controllers   :`);
    controllers.forEach((ctrl, i) => {
      console.log(`   [${i}] ${ctrl}`);
    });

    console.log("- Signatures:");
    for (let i = 0; i < v.length; i++) {
      console.log(`   [${i}] v: ${v[i]}, r: ${r[i]}, s: ${s[i]}`);
    }
  }
})();

// remix.execute('get_events.js')
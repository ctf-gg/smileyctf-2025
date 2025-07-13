export DEPLOYER_PRIVATE_KEY=35d7e3183bbe3e89907724a7c50a1e3f7207af30d169812534558f3591e27b31
cp -r /geth/config/ /config/
export BLOCKCHAIN_RPC_URL=http://0.0.0.0:8545
(cd /geth && ./entrypoint.sh) &
npm run prod
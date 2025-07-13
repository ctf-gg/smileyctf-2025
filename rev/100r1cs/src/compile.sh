python3 flag_to_input.py > input.json
circom flagchecker.circom --sym --r1cs --wasm # flagchecker. only valid binary input is flag. 
cd flagchecker_js
node generate_witness.js flagchecker.wasm ../input.json witness.wtns # assert flag valid. this only passes if this is the case.
cd ..
rm -rf flagchecker_js
rm -rf input.json
python3 stripsyms.py
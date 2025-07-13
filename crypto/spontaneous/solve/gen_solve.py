from EvilProver import Prover as EProver

p = EProver()
from fft import fft

poly = [p.domain_length+1337+i for i in range(p.domain_length)] # :3

evals = fft(poly, p.ω, p.p)

from EvilVerifier import Verifier as EVVerifier
def forge_prove(evals):
    i = 77623 # takes about 30 min to find single core.
    while True:
        p = EProver()
        p.seed = i
        proof = p.prove(evals)
        v = EVVerifier()
        v.seed = i
        if v.verify(proof["last_comm"], proof["roots"], proof["queries"], 2):
            print(f"Found valid proof with seed {i}")
            return i
        print(f"Invalid proof with seed {i}")
        i += 1

seed = forge_prove(evals)

from EvilValidProver import Prover as EVProver
p = EVProver()
p.seed = seed
proof = p.prove(evals)

v = EVVerifier()
v.seed = seed
print(v.verify(proof["last_comm"], proof["roots"], proof["queries"], 0))

from Verifier import Verifier
v = Verifier()
print(v.verify(proof["last_comm"], proof["roots"], proof["queries"], 0))
import json
open("solve.json", "w").write(json.dumps(proof, indent=4))
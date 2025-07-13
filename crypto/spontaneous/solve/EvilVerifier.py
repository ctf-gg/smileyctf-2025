from merkletree import MerkleTree
from ZKP import ZKP
from fft import ifft
class Verifier(ZKP):
    def verify(self, last_comm, roots, queries, max_degree):
        try:
            if len(roots) != self.r+1:
                print("Invalid number of roots")
                return False

            αs = []
            for root in roots[:-1]:
                self.transcript.put(root)
                αs.append(self.transcript.get_challenge())
            
            self.transcript.put(last_comm)

            ω = self.ω
            for r in range(0, self.r):
                dl = self.domain_length >> r
                indexes = self.indices(dl, self.s)
                qs = queries[r]
                root = roots[r]
                α = αs[r]
                if len(qs) != len(indexes):
                    return False
                for i, idx in enumerate(indexes):
                    if len(qs[i]) != 3:
                        return False
                    if any(len(x) != 2 for x in qs[i]):
                        return False
                    ay = qs[i][0][0]
                    by = qs[i][1][0]
                    cy = qs[i][2][0]
                    if dl <= 2*self.expansion_factor:
                        if not (ay == 0 and by == 0 and cy == 0):
                            print(f"Invalid values at index {i} for r={r}, ay={ay}, by={by}, cy={cy}, seed={self.seed}")
                            open("log.txt","a").write(f"Invalid values at index {i} for r={r}, ay={ay}, by={by}, cy={cy}, seed={self.seed}\n")
                            return False
                    else:
                        if not ((ay != 0) and (by != 0) and (cy != 0)):
                            #print(f"Invalid values at index {i} for r={r} 2")
                            return False
                ω **= 2
                ω %= self.p
            
            if len(last_comm) != self.expansion_factor:
                open("lol.txt","a").write(f"kys1{self.seed}\n")
                return False
            
            if roots[-1] != MerkleTree(last_comm).get_root():
                open("lol.txt","a").write(f"kys2{self.seed}\n")
                return False

            poly = ifft(last_comm, ω, self.p)
            deg_poly = poly.copy()
            while deg_poly and deg_poly[-1] == 0:
                deg_poly.pop(-1)
            deg = len(deg_poly) - 1
            assert self.domain_length//(2**self.r) == self.expansion_factor
            if deg > max_degree//(2**self.r):
                open("lol.txt","a").write(f"kys3{self.seed}\n")
                return False
            return True
        except Exception as e:
            return False
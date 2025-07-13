# not given to participants
from merkletree import MerkleTree
from ZKP import ZKP
import random
def random_zero(seed, points, x):
    points = points[:]
    r = random.Random(seed)
    idxs = r.choices(range(1, len(points)//2), k=len(points) // 4)
    for idx in idxs:
        points[idx] = x
        points[idx + len(points) // 2] = x
    return points

cache = {}
class Prover(ZKP):    
    def commit(self, points):
        commitment = []
        roots = []
        ω = self.ω
        inv2 = pow(2, -1, self.p)
        for _ in range(self.r):
            merkle = MerkleTree(points)
            root = merkle.get_root()
            roots.append(root)
            self.transcript.put(root)
            α = self.transcript.get_challenge()
            commitment.append(points)
            if len(points) >= self.expansion_factor*4:
                new_points = []
                for i in range(0, len(points)//2):
                    if (i, α, points[i], points[len(points)//2 + i]) in cache:
                        point = cache[(i, α, points[i], points[len(points)//2 + i])]
                    else:
                        m = α * pow(ω, -i, self.p)
                        point = inv2 * ((1 + m) * points[i] + (1 - m) * points[len(points)//2 + i])
                        if len(cache) < 2**20:
                            cache[(i, α, points[i], points[len(points)//2 + i])] = point
                    new_points.append(point % self.p)
            if len(points) == self.expansion_factor*4:
                new_points = random_zero(self.seed, new_points, 0)
            if len(points) < self.expansion_factor*4:
                new_points = [0] * (len(points)//2)
            points = new_points
            ω **= 2
            ω %= self.p
        self.transcript.put(points)
        commitment.append(points)
        roots.append(MerkleTree(points).get_root())
        return commitment, roots
    
    def query_idx(self, points, next_points, idx):
        idx2 = (idx + len(points) // 2) % len(points)
        idx3 = idx % len(next_points)
        #merkle = MerkleTree(points)
        #next_merkle = MerkleTree(next_points)
        return [[points[idx], []], [points[idx2], []], [next_points[idx3], []]]

    def query_idxs(self, points, next_points, indices):
        queries = []
        for idx in indices:
            queries.append(self.query_idx(points, next_points, idx))
        return queries

    def prove(self, points):
        commitment, roots = self.commit(points)
        queries = []
        for i in range(self.r):
            indices = self.indices(len(commitment[i]), self.s)
            queries.append(self.query_idxs(commitment[i], commitment[i + 1], indices))
        return {
            "last_comm": commitment[-1],
            "roots": roots,
            "queries": queries,
        }
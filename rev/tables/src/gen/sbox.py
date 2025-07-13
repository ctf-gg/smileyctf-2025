import random

class SBox:
    @staticmethod
    def identity(n: int) -> 'SBox':
        return SBox(list(range(n)))
    
    @staticmethod
    def random(n: int) -> 'SBox':
        table = list(range(n))
        random.shuffle(table)
        return SBox(table)
    
    @staticmethod
    def encrypt_bytes(pt: bytes, sboxes: list['SBox']) -> bytes:
        assert len(sboxes) == 2 * len(pt)
        ct = bytearray()
        for i, b in enumerate(pt):
            sbox_lo = sboxes[i * 2]
            sbox_hi = sboxes[i * 2 + 1]
            byte = sbox_lo.encrypt(b & 0x0f) | (sbox_hi.encrypt(b >> 4) << 4)
            ct.append(byte)
        return bytes(ct)
    
    @staticmethod
    def decrypt_bytes(ct: bytes, sboxes: list['SBox']) -> bytes:
        assert len(sboxes) == 2 * len(ct)
        pt = bytearray()
        for i, b in enumerate(ct):
            sbox_lo = sboxes[i * 2]
            sbox_hi = sboxes[i * 2 + 1]
            byte = sbox_lo.decrypt(b & 0x0f) | (sbox_hi.decrypt(b >> 4) << 4)
            pt.append(byte)
        return bytes(pt)

    def __init__(self, table: list[int]):
        self.table = table
        self.inverse = [0] * len(table)
        for i, v in enumerate(table):
            self.inverse[v] = i

    def encrypt(self, value: int) -> int:
        assert 0 <= value < len(self.table)
        return self.table[value]
    
    def decrypt(self, value: int) -> int:
        assert 0 <= value < len(self.inverse)
        return self.inverse[value]

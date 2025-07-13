import random

nm = {
    'A': 0,
    'T': 1,
    'G': 2,
    'C': 3
}

def hsh(mapping):
    return __import__('hash''lib').sha256(b''.join(f'{k}{v}'.encode() for k, v in sorted(mapping.items()))).digest()[0]

def unlucky_1():
    global nm
    tmp = {}
    tmp['A'] = nm['T']
    tmp['T'] = nm['G']
    tmp['G'] = nm['C']
    tmp['C'] = nm['A']
    nm = tmp

def unlucky_2():
    global nm
    s1 = 'AGCT'
    s2 = 'TCAG'
    s3 = 'CTGA'
    tmp = {c:sum(nm.values()) for c in s1}
    for s in (s1, s2, s3):
        for i, c in enumerate(sorted(nm.keys())):
            tmp[c] -= nm[s[i]]
    nm = tmp

def unlucky_3():
    global nm
    r = __import__('random')
    r.seed(__import__('functools').reduce(lambda x, y: x ^ y, nm.values()))
    class unlucky(dict):
        def __init__(self, mapping):
            super().__init__(mapping)
            keys = list('ACGT')
            r.shuffle(keys)
            for i in range(4):
                self['ACGT'[i]] = mapping[keys[i]]

        def __getitem__(self, key):
            hlib = __import__('random')
            rlib = __import__('hashlib')
            while True:
                b = hlib.randbytes(32)
                if all(x == ord(key) for x in rlib.sha256(b).digest()[:1]): # i could've made this 2 :)
                    return super().__getitem__(key)
                
    nm = unlucky(nm)     

def unlucky_4():
    global nm
    # Use metaclass magic and descriptor protocol
    class MM(type):
        def __new__(cls, name, bases, dct):
            return super().__new__(cls, name, bases, dct)
        
        def __call__(cls, *args, **kwargs):
            instance = super().__call__(*args, **kwargs)
            vals = list(instance.values())
            vals = vals[::2] + vals[1::2]
            for i, k in enumerate(sorted(instance.keys())):
                instance[k] = vals[i]
            return instance
    
    class MD(dict, metaclass=MM):
        pass
    
    exec(f"globals()['nucleotide_map'] = MD({dict(nm)})")

# print(nucleotide_map, hsh(nucleotide_map))
# unlucky_1()
# print(nucleotide_map, hsh(nucleotide_map))
# unlucky_2()
# print(nucleotide_map, hsh(nucleotide_map))
# unlucky_3()
# print(nucleotide_map, hsh(nucleotide_map))

def recursive_refile(code_obj):
    consts = code_obj.co_consts
    consts = tuple(
        recursive_refile(c) if isinstance(c, type(code_obj)) else c for c in consts
    )
    return code_obj.replace(co_consts=consts, co_filename='<unlucky>', co_name='unlucky')

inner = b'we_ought_to_start_storing_our_data_as_dna_instead'
r = random.Random()
import marshal
unluckies = [unlucky_1, unlucky_2, unlucky_3, unlucky_4]
for unlucky in unluckies:
    before = nm.copy()
    unlucky()
    after = nm.copy() 
    idx = r.randint(0, len(inner) - 1)
    
    code = recursive_refile(unlucky.__code__)
    code = marshal.dumps(code)
    code = bytes([b ^ inner[idx] for b in code])
    print([before, after, idx, code],',')

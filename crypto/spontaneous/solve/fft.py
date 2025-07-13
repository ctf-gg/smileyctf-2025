def fft(a, ω, p):
    n = len(a)
    if n == 1:
        return a[:]
    ωn = pow(ω, 2, p)
    e = fft(a[0::2], ωn, p)
    o = fft(a[1::2], ωn, p)
    result = [0] * n
    mult = 1
    for i in range(n // 2):
        result[i] = (e[i] + mult * o[i]) % p
        result[i + n // 2] = (e[i] - mult * o[i]) % p
        mult = (mult * ω) % p
    return result

def ifft(a, ω, p):
	result = fft(a, pow(ω, -1, p), p)
	return [((x * pow(len(a), -1, p)) % p) for x in result]


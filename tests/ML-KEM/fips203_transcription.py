# Copyright (c) The OpenPQC project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""ML-KEM written out from the text of FIPS 203 (13 August 2024), as an oracle for the tests.

Independent of OpenPQC and of mlkem-native: the hash functions are Python's hashlib (FIPS 202 through
OpenSSL), the zetas are computed from zeta = 17 and BitRev7 (Section 4.3), and no table or constant is copied
from an implementation. Slow, not constant time, never to be used for anything but tests.

Checked against NIST's own answers: all 435 cases of the ACVP vector sets that mlkem_acvp pins
(usnistgov/ACVP-Server 975de31e: keyGen, encapsulation, decapsulation with its implicit rejections, and both
key checks) give NIST's results when computed with this file, and with G(d) in place of G(d || k), the key
generation of the draft standard, the 75 keyGen cases do not. tests/ML-KEM/fips203_check.py uses it.

DEV injects single deviations from the standard (all off: FIPS 203), so that a test can show that it would see
one: fips203_check.py uses no_k_in_G for the control of its known-answer check.
"""
import hashlib

Q = 3329
N = 256
PARAMS = {512: dict(k=2, eta1=3, eta2=2, du=10, dv=4),
          768: dict(k=3, eta1=2, eta2=2, du=10, dv=4),
          1024: dict(k=4, eta1=2, eta2=2, du=11, dv=5)}

# deviations (all False/None = FIPS 203 final)
DEV = dict(no_k_in_G=False,          # Alg 13 line 1: G(d) instead of G(d||k) (FIPS 203 ipd)
           ji_swap=False,            # Alg 13/14: SampleNTT(rho||i||j) instead of rho||j||i
           compress_floor=False,     # (4.7): floor instead of round-half-up
           no_implicit_reject=False, # Alg 18 lines 9-10 omitted
           kbar_c_z=False,           # Alg 18 line 7: J(c||z) instead of J(z||c)
           kbar_sha3=False,          # Alg 18 line 7: SHA3-256 instead of SHAKE256
           G_order=False,            # Alg 17 line 1: G(H(ek)||m) instead of G(m||H(ek))
           dk_order=False,           # Alg 16 line 3: dk = dkPKE||ek||z||H(ek)
           no_ek_check=False,        # Section 7.2 modulus check omitted
           no_dk_check=False,        # Section 7.3 hash check omitted
           prf_eta2_for_y=False,     # Alg 14 line 10: eta2 instead of eta1 for y
           )


def G(c):
    h = hashlib.sha3_512(c).digest()
    return h[:32], h[32:]


def H(s):
    return hashlib.sha3_256(s).digest()


def J(s):
    return hashlib.shake_256(s).digest(32)


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


ZETA = [pow(17, bitrev7(i), Q) for i in range(128)]
GAMMA = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]


def bytes_to_bits(B):
    return [(byte >> j) & 1 for byte in B for j in range(8)]


def bits_to_bytes(b):
    out = bytearray(len(b) // 8)
    for i, bit in enumerate(b):
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def byte_encode(F, d):
    b = []
    for a in F:
        for j in range(d):
            b.append((a >> j) & 1)
    return bits_to_bytes(b)


def byte_decode(B, d):
    b = bytes_to_bits(B)
    m = Q if d == 12 else 1 << d
    return [sum(b[i * d + j] << j for j in range(d)) % m for i in range(N)]


def compress(x, d):
    # round(2^d / q * x) mod 2^d, round-half-up, exact rational arithmetic
    if DEV["compress_floor"]:
        return ((x << d) // Q) % (1 << d)
    return (((x << d) * 2 + Q) // (2 * Q)) % (1 << d)


def decompress(y, d):
    return ((y * Q) * 2 + (1 << d)) // (2 << d)


def sample_ntt(B):
    n = 840
    while True:
        stream = hashlib.shake_128(B).digest(n)
        a, j, pos = [], 0, 0
        while j < N and pos + 3 <= n:
            C = stream[pos:pos + 3]
            pos += 3
            d1 = C[0] + 256 * (C[1] % 16)
            d2 = C[1] // 16 + 16 * C[2]
            if d1 < Q:
                a.append(d1)
                j += 1
            if d2 < Q and j < N:
                a.append(d2)
                j += 1
        if j == N:
            return a
        n *= 2


def sample_cbd(B, eta):
    b = bytes_to_bits(B)
    f = []
    for i in range(N):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)
    return f


def ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETA[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETA[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def mul_ntt(f, g):
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMA[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def gen_A(rho, k):
    A = [[None] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A[i][j] = sample_ntt(rho + (bytes([i, j]) if DEV["ji_swap"] else bytes([j, i])))
    return A


def kpke_keygen(d, p):
    k, eta1 = p["k"], p["eta1"]
    rho, sigma = G(d if DEV["no_k_in_G"] else d + bytes([k]))
    A = gen_A(rho, k)
    Nc = 0
    s, e = [], []
    for _ in range(k):
        s.append(sample_cbd(PRF(eta1, sigma, Nc), eta1))
        Nc += 1
    for _ in range(k):
        e.append(sample_cbd(PRF(eta1, sigma, Nc), eta1))
        Nc += 1
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    t_hat = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = add(acc, mul_ntt(A[i][j], s_hat[j]))
        t_hat.append(add(acc, e_hat[i]))
    ek = b"".join(byte_encode(t, 12) for t in t_hat) + rho
    dk = b"".join(byte_encode(s, 12) for s in s_hat)
    return ek, dk


def kpke_encrypt(ek, m, r, p):
    k, eta1, eta2, du, dv = p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]
    Nc = 0
    t_hat = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:384 * k + 32]
    A = gen_A(rho, k)
    y, e1 = [], []
    ey = eta2 if DEV["prf_eta2_for_y"] else eta1
    for _ in range(k):
        y.append(sample_cbd(PRF(ey, r, Nc), ey))
        Nc += 1
    for _ in range(k):
        e1.append(sample_cbd(PRF(eta2, r, Nc), eta2))
        Nc += 1
    e2 = sample_cbd(PRF(eta2, r, Nc), eta2)
    y_hat = [ntt(x) for x in y]
    u = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = add(acc, mul_ntt(A[j][i], y_hat[j]))   # A transpose
        u.append(add(ntt_inv(acc), e1[i]))
    mu = [decompress(b, 1) for b in byte_decode(m, 1)]
    acc = [0] * N
    for i in range(k):
        acc = add(acc, mul_ntt(t_hat[i], y_hat[i]))
    v = add(add(ntt_inv(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, du) for x in ui], du) for ui in u)
    c2 = byte_encode([compress(x, dv) for x in v], dv)
    return c1 + c2


def kpke_decrypt(dk, c, p):
    k, du, dv = p["k"], p["du"], p["dv"]
    c1 = c[:32 * du * k]
    c2 = c[32 * du * k:32 * (du * k + dv)]
    u = [[decompress(x, du) for x in byte_decode(c1[32 * du * i:32 * du * (i + 1)], du)] for i in range(k)]
    v = [decompress(x, dv) for x in byte_decode(c2, dv)]
    s_hat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * N
    for i in range(k):
        acc = add(acc, mul_ntt(s_hat[i], ntt(u[i])))
    w = sub(v, ntt_inv(acc))
    return byte_encode([compress(x, 1) for x in w], 1)


def keygen_internal(d, z, level):
    p = PARAMS[level]
    ek, dkpke = kpke_keygen(d, p)
    if DEV["dk_order"]:
        dk = dkpke + ek + z + H(ek)
    else:
        dk = dkpke + ek + H(ek) + z
    return ek, dk


def encaps_internal(ek, m, level):
    p = PARAMS[level]
    K, r = G(H(ek) + m) if DEV["G_order"] else G(m + H(ek))
    c = kpke_encrypt(ek, m, r, p)
    return K, c


def decaps_internal(dk, c, level, info=None):
    p = PARAMS[level]
    k = p["k"]
    dkpke = dk[:384 * k]
    ekpke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m2 = kpke_decrypt(dkpke, c, p)
    K2, r2 = G(m2 + h)
    if DEV["kbar_sha3"]:
        Kbar = hashlib.sha3_256(z + c).digest()
    elif DEV["kbar_c_z"]:
        Kbar = J(c + z)
    else:
        Kbar = J(z + c)
    c2 = kpke_encrypt(ekpke, m2, r2, p)
    rejected = c != c2
    if info is not None:
        info["rejected"] = rejected
    if rejected and not DEV["no_implicit_reject"]:
        K2 = Kbar
    return K2


def ek_check(ek, level):
    """Section 7.2: type check and modulus check"""
    k = PARAMS[level]["k"]
    if len(ek) != 384 * k + 32:
        return False
    if DEV["no_ek_check"]:
        return True
    test = b"".join(byte_encode(byte_decode(ek[384 * i:384 * (i + 1)], 12), 12) for i in range(k))
    return test == ek[:384 * k]


def dk_check(dk, level):
    """Section 7.3 items 2 and 3: type check and hash check"""
    k = PARAMS[level]["k"]
    if len(dk) != 768 * k + 96:
        return False
    if DEV["no_dk_check"]:
        return True
    return H(dk[384 * k:768 * k + 32]) == dk[768 * k + 32:768 * k + 64]


def ct_check(c, level):
    p = PARAMS[level]
    return len(c) == 32 * (p["du"] * p["k"] + p["dv"])

"""
This file contains procedures for common algebraic operations over:
- polynomials in Z_q[x] / (x^n + 1)
- vectors with such polynomials as entries
Polynomials are typically noted f, g, h.
Vectors are typically noted s, t, u, v, w.
"""
# High-quality randomness
import sys
if sys.version_info >= (3, 6):
    from secrets import randbits
from ntt import ntt, mul_ntt, intt


def ntt_mat(A):
    k = len(A)
    ell = len(A[0])
    return [[ntt(A[i][j]) for j in range(ell)] for i in range(k)]


def ntt_vec(v):
    k = len(v)
    return [ntt(v[i]) for i in range(k)]


def intt_vec(v):
    k = len(v)
    return [intt(v[i]) for i in range(k)]


def add_poly(f, g, q):
    """
    Addition of two polynomials mod q.
    """
    assert(len(g) == len(f))
    n = len(f)
    return [(f[i] + g[i]) % q for i in range(n)]


def sub_poly(f, g, q):
    """
    Subtraction of two polynomials mod q.
    """
    assert(len(g) == len(f))
    n = len(f)
    return [(f[i] - g[i]) % q for i in range(n)]


def random_poly(n, q):
    """
    Generate a random vector of polynomials.
    """
    log_q = q.bit_length()
    rep = [0] * n
    i = 0
    while(i < n):
        x = randbits(log_q)
        if (x < q):
            rep[i] = x
            i += 1
    return rep


def add_vec(u, v, q):
    """
    Addition of two vectors of polynomials.
    """
    assert(len(u) == len(v))
    k = len(u)
    return [add_poly(u[i], v[i], q) for i in range(k)]


def sub_vec(u, v, q):
    """
    Subtraction of two vectors of polynomials.
    """
    assert(len(u) == len(v))
    k = len(u)
    return [sub_poly(u[i], v[i], q) for i in range(k)]


def center_vec(u, q):
    """
    Center the modular coefficients of a vector around 0.
    """
    mid = q >> 1
    k = len(u)
    n = len(u[0])
    for i in range(k):
        for j in range(n):
            u[i][j] = ((u[i][j] + mid) % q) - mid


def shift_vec_inplace(v, q, log_p):
    """
    In-place modulus shifting of a vector of polynomials.
    Each coefficient is shifted by lp bits.
    """
    k = len(v)
    n = len(v[0])
    for i in range(k):
        for j in range(n):
            v[i][j] = (v[i][j] >> log_p) % q
    return


def random_vec(ell, n, q):
    """
    Generate a random vector of polynomials.
    """
    return [random_poly(n, q) for j in range(ell)]


def mul_mat_vec_ntt(A, s, q):
    """
    Matrix × vector multiplication.
    We assume q = 2^49 - 2^30 + 1
    """
    k = len(A)
    ell = len(A[0])
    n = len(A[0][0])
    t = [[0 for j in range(n)] for i in range(k)]
    for i in range(k):
        for j in range(ell):
            t[i] = add_poly(t[i], mul_ntt(A[i][j], s[j]), q)
    return t


def mul_poly_vec_ntt(c, s, q):
    """
    Polynomial × vector multiplication.
    """
    ell = len(s)
    z = [mul_ntt(c, s[j]) for j in range(ell)]
    return z


# def mul_chal_vec(c, s, q):
#     k = len(s)
#     n = len(s[0])
#     rep = [[0] * n] * k
#     assert(len(c) == n)
#     s_rot = s[:][:]
#     for j in range(n):
#         s_rot = [[-s_rot[i][-1]] + s_rot[i][:-1] for i in range(k)]
#         if (c[j] == 1):
#             rep = add_vec(rep, s_rot, q)
#         if (c[j] == -1):
#             rep = sub_vec(rep, s_rot, q)
#     return rep


def leftshift_vec(v, p, q):
    """
    Multiplication of a vector by (2^p).
    """
    k = len(v)
    n = len(v[0])
    w = [[(v[i][idx] << p) for idx in range(n)] for i in range(k)]
    return w


def compute_norms(v):
    """
    Compute the squared-euclidean and infinity norms of a vector.
    """
    k = len(v)
    n = len(v[0])
    euclidean = 0
    infinity = 0
    for i in range(k):
        for j in range(n):
            euclidean += (v[i][j] * v[i][j])
            infinity = max(abs(v[i][j]), infinity)
    return euclidean, infinity
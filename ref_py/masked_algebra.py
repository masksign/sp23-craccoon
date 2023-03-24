"""
This file contains procedures for common algebraic operations over:
- _masked_ polynomials in Z_q[x] / (x^n + 1)
- _masked_ vectors with such polynomials as entries
Masked polynomials are typically noted mf, mg, mh.
Masked vectors are typically noted mu, mv, mw.
"""
from algebra import add_poly, sub_poly, random_poly
from algebra import mul_poly_vec_ntt
from ntt import ntt, intt, mul_ntt, mul_zq as mul_poly


def ntt_mvec(v):
    d = len(v)
    k = len(v[0])
    return [[ntt(v[i][j]) for j in range(k)] for i in range(d)]


def intt_mvec(v):
    d = len(v)
    k = len(v[0])
    return [[intt(v[i][j]) for j in range(k)] for i in range(d)]


def random_mpoly(d, n, q):
    """
    Generate a random masked polynomial.
    """
    return [random_poly(n, q) for i in range(d)]


def encode_poly(f, d, q):
    """
    Generate a uniformly random order-d encoding of a polynomial f.
    """
    assert(d > 0)
    n = len(f)
    # Generate (d - 1) random shares
    mf = random_mpoly(d - 1, n, q)
    # The last share is the input polynomial minus all the shares
    mf += [f[::]]
    for i in range(d - 1):
        mf[-1] = sub_poly(mf[-1], mf[i], q)
    return mf


def decode_mpoly(mf, q):
    """
    Recover a polynomial from its order-d encoding.
    """
    d = len(mf)
    # f is the sum of the entries of mf
    f = mf[0][::]
    for i in range(1, d):
        f = add_poly(f, mf[i], q)
    return f


def add_mpoly(mf, mg, q):
    """
    Add two masked polynomials mod q.
    """
    assert(len(mf) == len(mg))
    d = len(mf)
    return [add_poly(mf[i], mg[i], q) for i in range(d)]


def mul_mpoly_poly_ntt(mf, g, q):
    """
    Compute the multiplication mf * g mod q.
    The first polynomial (mf) is masked, the second (g) is in clear.
    NTT format.
    """
    assert(len(mf[0]) == len(g))
    return [mul_ntt(poly, g) for poly in mf]


def mul_mpoly_poly(mf, g, q):
    return [mul_poly(poly, g, q) for poly in mf]


def encode_vec(u, d, q):
    """
    Generate a uniformly random order-d encoding of a polynomial u.
    """
    assert(d > 0)
    return [encode_poly(poly, d, q) for poly in u]


def decode_mvec(mu, q):
    """
    Recover a vector from its order-d encoding.
    """
    return [decode_mpoly(mpoly, q) for mpoly in mu]


def random_mvec(ell, d, n, q):
    """
    Generate a random masked vector.
    """
    return [random_mpoly(d, n, q) for i in range(ell)]


def add_mvec(mu, mv, q):
    """
    Add two masked vectors of polynomials mod q.
    """
    assert(len(mu) == len(mv))
    k = len(mu)
    return [add_mpoly(mu[i], mv[i], q) for i in range(k)]


def mul_mvec_poly_ntt(mu, f, q):
    """
    Compute the multiplication mu * f mod q.
    The vector mu is masked, the polynomial f is in clear.
    """
    mv = [mul_poly_vec_ntt(f, mpoly, q) for mpoly in mu]
    return mv


def mul_mat_mvec_ntt(A, ms, q):
    k = len(A)
    ell = len(A[0])
    n = len(A[0][0])
    d = len(ms[0])
    mt = [[[0 for idx in range(n)] for j in range(d)] for i in range(k)]
    for i in range(k):
        for j in range(ell):
            mt[i] = add_mpoly(mt[i], mul_mpoly_poly_ntt(ms[j], A[i][j], q), q)
    return mt


def refresh_mpoly_bcpz(mf, q):
    """
    Quasilinear refresh gadget (Algorithm 6: RefreshMasks in [BCPZ16]).
    The order-d masked polynomial to refresh is represented as
    a size-d list of polynomials.
    """
    d = len(mf)
    # How to check if a given number is a power of two?
    # https://stackoverflow.com/a/57025941
    assert (d & (d - 1) == 0) and (d != 0)
    n = len(mf[0])

    if (d == 1):
        return

    else:
        d2 = d // 2
        # First linear pass
        for i in range(d2):
            r = random_poly(n, q)
            mf[i] = add_poly(mf[i], r, q)
            mf[d2 + i] = sub_poly(mf[d2 + i], r, q)
        # Recursion
        refresh_mpoly(mf[:d2], q)
        refresh_mpoly(mf[d2:], q)
        # Second linear pass (identical to first one)
        for i in range(d2):
            r = random_poly(n, q)
            mf[i] = add_poly(mf[i], r, q)
            mf[d2 + i] = sub_poly(mf[d2 + i], r, q)
        return


def zero_mpoly(d, n):
    """
    All-zero masked polynomial (the actual shares are at zero, it has no randomness).
    """
    return [[0 for j in range(n)] for i in range(d)]


def zero_encoding_mpoly(d, n, q):
    """
    Zero-encoding gadget
    (Algorithm 6: ZeroEncoding in http://www.matthieurivain.com/files/habilitation-thesis.pdf)
    The order-d masked zero polynomial generated is represented as a size-d list of polynomials.
    """
    if (d == 2):
        mf = zero_mpoly(d, n)
        r = random_poly(n, q)
        mf[0] = add_poly(mf[0], r, q)
        mf[1] = sub_poly(mf[1], r, q)
        return mf
    else:
        mf = zero_encoding_mpoly(d // 2, n, q) + zero_encoding_mpoly(d // 2, n, q)
        for i in range(d // 2):
            r = random_poly(n, q)
            mf[i] = add_poly(mf[i], r, q)
            mf[i + d // 2] = sub_poly(mf[i + d // 2], r, q)
        return mf


def ios_sni_refresh_mpoly(mf, q):
    """
    Quasilinear refresh gadget over a masked polynomial
    (Algorithm 7: "IOS refresh gadget" in http://www.matthieurivain.com/files/habilitation-thesis.pdf)
    This algorithm is proven IOS in the eprint version of [GPRV21], and SNI in http://www.theses.fr/2021UPASG095.
    """
    d = len(mf)
    assert (d & (d - 1) == 0) and (d != 0)
    n = len(mf[0])

    mg = zero_encoding_mpoly(d, n, q)
    mf[:] = add_mpoly(mf, mg, q)


def refresh_mpoly(mf, q):
    """
    Interface for the refresh gadget. We may either choose the BCPZ or IOS/SNI gadget.
    """
    ios_sni_refresh_mpoly(mf, q)


def refresh_mvec(mv, q):
    """
    The order-d masked vector of dimension ell to refresh is represented as
    a size-ell list of size-d lists of polynomials.
    """
    for i in range(len(mv)):
        refresh_mpoly(mv[i], q)
    # mv[:] = mv


def orderswitch_mvec(mv, q):
    """
    OrderSwitch gadget.
    For now, the new masking order d' is hardcoded to d' = 2d.
    """
    ell = len(mv)
    d = len(mv[0])
    n = len(mv[0][0])

    mv2 = [mv[i] + zero_mpoly(d, n) for i in range(ell)]
    refresh_mvec(mv2, q)
    return mv2

"""
Test the code with:
> make test
"""
# https://stackoverflow.com/a/25823885/4143624
from algebra import *
from ntt import mul_zq as mul_poly, q as q0
# from experimental.masked_shift import *
from masked_algebra import *
# from timeit import default_timer as timer
from random import randint
from raccoon import *

def schoolbook(f, g, n, q):
    assert(len(f) == n)
    assert(len(g) == n)

    h = [0] * (2 * n)
    for i in range(n):
        for j in range(n):
            h[i + j] += f[i] * g[j]
            h[i + j] %= q
    fg = [(h[i] - h[i + n]) % q for i in range(n)]
    return fg


def test_mul_poly(n, q, iterations=500):
    """
    Test the mul_poly() functions against schoolbook multiplication.
    """
    for _ in range(iterations):
        f = [randint(0, q) for i in range(n)]
        g = [randint(0, q) for i in range(n)]
        fg = mul_poly(f, g, q)
        fg_schoolbook = schoolbook(f, g, n, q)
        # print(fg)
        # print(fg_schoolbook)
        assert(fg == fg_schoolbook)
    return True


def test_encode_poly(d, n, q, iterations=500):
    """
    Test the encode_poly(), refresh_mpoly(), and decode_mpoly() functions.
    """
    for _ in range(iterations):
        f = random_poly(n, q)
        mf = encode_poly(f, d, q)
        refresh_mpoly(mf, q)
        fp = decode_mpoly(mf, q)
        assert(f == fp)
    return True


def test_encode_vec(ell, d, n, q, iterations=500):
    """
    Test the encode_vec(), refresh_mvec(), and decode_mvec() functions.
    """
    for _ in range(iterations):
        v = random_vec(ell, n, q)
        mv = encode_vec(v, d, q)
        refresh_mvec(mv, q)
        vp = decode_mvec(mv, q)
        assert(v == vp)
    return True


def test_orderswitch_mvec(ell, d, n, q, iterations=500):
    """
    Test the encode_vec(), refresh_mvec(), and decode_mvec() functions.
    """
    for _ in range(iterations):
        v = random_vec(ell, n, q)
        mv = encode_vec(v, d, q)
        mv2 = orderswitch_mvec(mv, q)
        vp = decode_mvec(mv2, q)
        assert(v == vp)
    return True


def test_add_mpoly(d, n, q, iterations=500):
    """
    Test the add_mpoly() function.
    """
    for _ in range(iterations):
        f = random_poly(n, q)
        g = random_poly(n, q)
        h = add_poly(f, g, q)
        mf = encode_poly(f, d, q)
        mg = encode_poly(g, d, q)
        mh = add_mpoly(mf, mg, q)
        hp = decode_mpoly(mh, q)
        assert(h == hp)
    return True


def test_approxshift_mvec_inplace(d, k, n, q, lp, iterations=500):
    qp = q >> lp
    m = 0
    D = {x:0 for x in range(-(d >> 1), (d >> 1) + 1)}
    for _ in range(iterations):
        mv = random_mvec(k, d, n, q)
        v1 = decode_mvec(mv, q)
        shift_vec_inplace(v1, qp, lp)

        approxshift_mvec_inplace(mv, lp, qp)
        v2 = decode_mvec(mv, qp)

        diff = sub_vec(v2, v1, qp)
        center_vec(diff, qp)
        flat_diff =  [x for elt in diff for x in elt]
        for x in flat_diff:
            D[x] += 1
        mean = sum(flat_diff) / (n * k)
        m += mean
    for x in D:
        print (x, D[x])
    print(str(lp).ljust(5), m / iterations)


# def test_sub_mpoly_poly_inplace(d, n, log_q, iterations=500):
#     """
#     Test the sub_mpoly_poly_inplace() function.
#     """
#     mask = (1 << log_q) - 1
#     for _ in range(iterations):
#         f = random_poly(n, log_q)
#         g = random_poly(n, log_q)
#         mf = encode_poly(f, d, log_q)
#         for idx in range(n):
#             f[idx] = (f[idx] - g[idx]) & mask
#         sub_mpoly_poly_inplace(mf, g, log_q)
#         fp = decode_mpoly(mf, log_q)
#         assert(f == fp)
#     return True


def test_mul_mpoly_poly(d, n, q, iterations=500):
    """
    Test the mul_mpoly_poly and mul_mpoly_poly_inplace() function.
    """
    # Regular version
    for _ in range(iterations):
        f = random_poly(n, q)
        g = random_poly(n, q)
        mf = encode_poly(f, d, q)
        h = mul_poly(f, g, q)
        mh = mul_mpoly_poly(mf, g, q)
        hp = decode_mpoly(mh, q)
        assert(h == hp)
    # Inplace version
    # for _ in range(iterations):
    #     f = random_poly(n, q)
    #     g = random_poly(n, q)
    #     mf = encode_poly(f, d, q)
    #     f = mul_poly(f, g, q)
    #     mf = mul_mpoly_poly(mf, g, q)
    #     fp = decode_mpoly(mf, q)
    #     assert(f == fp)
    return True


# def test_mod_mpoly(d, n, log_q, log_p, iterations=500):
#     """
#     Test the mod_mpoly() function.
#     """
#     p = 1 << log_p
#     for _ in range(iterations):
#         f = random_poly(n, log_q)
#         mf = encode_poly(f, d, log_q)
#         h = mod_poly(f, p)
#         mh = mod_mpoly(mf, p)
#         hp = decode_mpoly(mh, log_p)
#         assert(h == hp)
#     return True


def test_add_mvec(ell, d, n, q, iterations=500):
    """
    Test the add_mvec() function.
    """
    for _ in range(iterations):
        u = random_vec(ell, n, q)
        v = random_vec(ell, n, q)
        w = add_vec(u, v, q)
        mu = encode_vec(u, d, q)
        mv = encode_vec(v, d, q)
        mw = add_mvec(mu, mv, q)
        wp = decode_mvec(mw, q)
        assert(w == wp)
    return True


# def test_sub_mvec_vec_inplace(ell, d, n, log_q, iterations=500):
#     """
#     Test the add_mvec() function.
#     """
#     for _ in range(iterations):
#         u = random_vec(ell, n, log_q)
#         v = random_vec(ell, n, log_q)
#         mu = encode_vec(u, d, log_q)
#         u = sub_vec(u, v, log_q)
#         sub_mvec_vec_inplace(mu, v, log_q)
#         up = decode_mvec(mu, log_q)
#         assert(u == up)
#     return True


# def test_mul_mvec_poly(ell, d, n, q, iterations=500):
#     """
#     Test the mul_mvec_poly() function.
#     """
#     for _ in range(iterations):
#         u = random_vec(ell, n, q)
#         f = random_poly(n, q)
#         v = mul_poly_vec(f, u, q)
#         mu = encode_vec(u, d, q)
#         mv = mul_mvec_poly(mu, f, q)
#         vp = decode_mvec(mv, q)
#         assert(v == vp)
#     return True


# def test_mul_mat_mvec(k, ell, d, n, q, iterations=500):
#     for _ in range(iterations):
#         A = [random_vec(ell, n, q) for i in range(k)]
#         u = random_vec(ell, n, q)
#         v = mul_mat_vec(A, u, q)
#         mu = encode_vec(u, d, q)
#         mv = mul_mat_mvec(A, mu, q)
#         vp = decode_mvec(mv, q)
#         assert(v == vp)
#     return True


# def test_mod_mvec(ell, d, n, log_q, log_p, iterations=500):
#     """
#     Test the mod_mvec() function.
#     """
#     p = 1 << log_p
#     for _ in range(iterations):
#         u = random_vec(ell, n, log_q)
#         mu = encode_vec(u, d, log_q)
#         v = mod_vec(u, p)
#         mv = mod_mvec(mu, p)
#         vp = decode_mvec(mv, log_p)
#         assert(v == vp)
#     return True

# 
# def test_encode_int(d, log_q, iterations=500):
#     for _ in range(iterations):
#         x = randbits(log_q)
#         mx = encode_int(x, d, log_q)
#         refresh_linear_mint_inplace(mx, log_q)
#         xp = decode_mint(mx, log_q)
#         assert(x == xp)
#     return True


# 
# def test_approx_round(d, log_q, log_p, iterations=500):
#     L = []
#     x = randbits(log_q)
#     p2 = 1 << (log_p - 1)
#     p = 1 << log_p
#     q_p = 1 << (log_q - log_p)
#     q_p2 = 1 << (log_q - log_p - 2)
#     for _ in range(iterations):
#         mx = encode_int(x, d, log_q)
#         my = approx_round(mx, k, log_p)
#         y = decode_mint(my, log_q - log_p)
#         xs = (x + p2) >> log_p
#         diff = ((xs - y + q_p2) % q_p) - q_p2
#         L += [diff]
#     P = {}
#     for elt in sorted(set(L)):
#         P[elt] = L.count(elt)
#     print(x, x % p)
#     print(P)


def create_offsets():
    d = 32
    D = {1:0}
    for i in range(2, 44):
        D[i] = D[i - 1] + (d - 1.) / (1 << i)
    for i in range(20, 44):
        D[i] = D[i - 1] - (d - 1.) / (1 << (i - 18))
    for i in D:
        print(str(i).ljust(5), D[i])


# Run all the tests
if (__name__ == "__main__"):
    q = q0
    # log_p = 2
    d = 8
    n = 32
    ell = 2
    k = 4
    # test_mul_poly(n, q, iterations=500)
    # test_encode_poly(d, n, q, iterations=500)
    # test_encode_vec(ell, d, n, q, iterations=500)
    # test_orderswitch_mvec(ell, d, n, q, iterations=500)
    # test_add_mpoly(d, n, q, iterations=500)
    # test_mul_mpoly_poly(d, n, q, iterations=500)
    # test_add_mvec(ell, d, n, q, iterations=500)
    # test_mul_mat_mvec(k, ell, d, n, q, iterations=500)
    # for log_p in range(1,44):
    #     test_approxshift_mvec_inplace(d, k, n, q, log_p, iterations=1000)
    test_approxshift_mvec_inplace(d, k, n, q, 8, iterations=100000)
    test_approxshift_mvec_inplace(d, k, n, q, 43, iterations=100000)
    # create_offsets()

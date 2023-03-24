"""
Implementation of Raccoon for prime moduli.
"""
from dataclasses import dataclass
from Crypto.Hash import SHAKE256
from timeit import default_timer as timer
from math import ceil
from ntt import ntt, q
from algebra import \
    add_vec, sub_vec, center_vec, \
    leftshift_vec, shift_vec_inplace, compute_norms, \
    ntt_mat, mul_poly_vec_ntt, intt_vec, mul_mat_vec_ntt, ntt_vec
#from masked_algebra import \
#    random_mvec, decode_mvec, add_mvec, refresh_mvec, orderswitch_mvec, \
#    ntt_mvec, intt_mvec, mul_mat_mvec_ntt, mul_mvec_poly_ntt
from masked_algebra import \
     decode_mvec, add_mvec, zero_mpoly, add_mpoly, \
     ntt_mvec, intt_mvec, mul_mat_mvec_ntt, mul_mvec_poly_ntt
from algebra import add_poly, sub_poly

import sys
assert sys.version_info >= (3, 6)
# High-quality randomness
#if sys.version_info >= (3, 6):
#    from secrets import randbitsd

from parameter_sets import *
#from golomb_coding import golomb_coding


BYTEORDER = "little"

#   [debug] non-cryptographic random
from debug_rand import debug_rand
fake_rand = debug_rand()
randbits = fake_rand.randbits

#   [debug] polynomial (mod q) checksum of matrices/vectors

def debug_qsum(lab, mat):
    s = 31337
    for vec in mat:
        for poly in vec:
            for coeff in poly:
                s = (3 * s + coeff) % q
    print(f'{lab}[{len(mat)}][{len(mat[0])}][{len(mat[0][0])}]: {s}')

#   [debug] deterministic random

def random_poly(n, q):
    return [fake_rand.randbelow(q) for i in range(n)]

def random_mvec(ell, d, n, q):
    return [[ random_poly(n, q) for j in range(d)] for k in range(ell)]

#   [debug] copied here from masked_algebra.py -- using the fake random

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

#   end

# Precomputed with experimental/test.sage
corr_terms = {
    6: 0.4843,
    7: 0.4922,
    8: 0.4960,
    9: 0.4981,
    10: 0.4990,
    11: 0.4995,
    12: 0.4997,
    13: 0.4998,
    14: 0.5000,
    15: 0.4999,
    16: 0.4999,
    17: 0.5000,
    18: 0.5000,
    19: 0.4999,
    20: 0.2499,
    21: 0.1249,
    22: 0.06248,
    23: 0.03113,
    24: 0.01555,
    25: 0.2577,
    26: 0.1289,
    27: 0.3144,
    28: 0.4071,
    29: 0.4536,
    30: 0.4769,
    31: 0.4883,
    32: 0.4942,
    33: 0.4971,
    34: 0.4985,
    35: 0.4992,
    36: 0.4996,
    37: 0.2497,
    38: 0.3749,
    39: 0.4374,
    40: 0.4686,
    41: 0.4844,
    42: 0.4921,
    43: 0.2481,
}

#   [debug]

def get_corr_term(d, lp):

    if lp in corr_terms:
        corr_term = int((d - 1) * corr_terms[lp] * (1 << lp) / d)
    else:
        corr_term = 0

    return corr_term

def approxshift_mvec_inplace(mv, lp, q):
    """
    ApproxShift inplace gadget applied to a masked vector.
    - mv is a masked vector of polynomials
    - each coefficient is shifted (right) by lp bits
    - each coefficient is the reduced modulo q
    """
    k = len(mv)
    d = len(mv[0])
    n = len(mv[0][0])

    if lp in corr_terms:
        corr_term = int((d - 1) * corr_terms[lp] * (1 << lp) / d)
    else:
        corr_term = 0

    # print("d= ", d, "  lp= ", lp, "  corr_term= ", corr_term)

    for i_poly in range(k):
        for i_share in range(d):
            for i_coef in range(n):
                mv[i_poly][i_share][i_coef] += corr_term
                mv[i_poly][i_share][i_coef] >>= lp
                mv[i_poly][i_share][i_coef] %= q


def golomb_size(x, k):
    # if x = 0, we don't need to encode the sign
    if (x == 0):
        return len(golomb_coding(x, k))
    else:
        return len(golomb_coding(x, k)) + 1


def encode_hint(h):
    """
    Very quick test to see which encoding is the best for the hint
    It doesn't return the encoding, just compute and print encoding sizes
    """
    flat_list = [item for sublist in h for item in sublist]
    print("")
    print("2 ", sum(golomb_size(x, 2) for x in flat_list) // 8)
    print("4 ", sum(golomb_size(x, 4) for x in flat_list) // 8)
    print("8 ", sum(golomb_size(x, 8) for x in flat_list) // 8)
    print("16", sum(golomb_size(x, 16) for x in flat_list) // 8)



@dataclass
class Param:
    """
    Dataclass for parameter sets of Raccoon.
    """
    target_bitsec: int
    q: int
    # lq: int
    # lqt: int
    lpt: int
    # lqw: int
    lpw: int
    n: int
    k: int
    ell: int
    w: int
    B22: int
    Boo: int
    d: int


# raccoon_128_50 = Param(target_bitsec=128, \
#     q=q, lpt=8, lpw=43, \
#     n=512, k=8, ell=3, w=19, B22=15000, Boo=8, d=32)

# With lpt=11
raccoon_128_43 = Param(target_bitsec=128, \
    q=q, lpt=11, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=16386, Boo=8, d=32)

# With lpt=10
raccoon_128_43 = Param(target_bitsec=128, \
    q=q, lpt=10, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=16386, Boo=8, d=32)

#   --- table

raccoon_128 = Param(target_bitsec=128, \
    q=q, lpt=10, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=16386, Boo=8, d=32)

raccoon_192 = Param(target_bitsec=192, \
    q=q, lpt=6, lpw=40, \
    n=512, k=11, ell=5, w=31, B22=16386, Boo=8, d=32)

raccoon_256 = Param(target_bitsec=256, \
    q=q, lpt=7, lpw=42, \
    n=512, k=14, ell=6, w=44, B22=32768, Boo=8, d=32)




def expand_seed(param, seed):
    """
    Expand a seed into a public matrix A using SHAKE256:
    - A has k lines and ell columns
    - each cell A[i][j] contains a polynomial of degree < n and coefficients < (2 ** lq)
    """
    n = param.n
    k = param.k
    ell = param.ell
    q = param.q
    # Initialise matrix
    A = [[[0 for idx in range(n)] for j in range(ell)] for i in range(k)]

    # The seed is given as input to the seed expander
    shake = SHAKE256.new()
    shake.update(seed)
    bytespercoef = ceil(q.bit_length() / 8)
    mask = (1 << q.bit_length()) - 1

    # The output of the seed expander become the coefficients of A
    # We perform some rejection sampling.
    for i_row in range(k):
        for i_col in range(ell):
            for i_coef in range(n):
                while(1):
                    coef_bytes = shake.read(bytespercoef)
                    coef_int = int.from_bytes(coef_bytes, BYTEORDER) & mask
                    if (coef_int < q):
                        break
                A[i_row][i_col][i_coef] = coef_int
    return A


def challenge_hash(param, msg, w):
    """
    Given the message and commitment, compute the challenge for the signature in compact form (a single hash).
    """
    # Fetch parameters
    lqw = (param.q >> param.lpw).bit_length()
    k = param.k
    n = param.n
    assert(len(w) == k)
    assert(len(w[0]) == n)

    bytespercoef = ceil(lqw / 8)
    shake = SHAKE256.new()
    # Perhaps hash the public key as well?
    # Apply https://eprint.iacr.org/2020/1525?
    for i in range(k):
        for idx in range(n):
            shake.update(w[i][idx].to_bytes(bytespercoef, byteorder=BYTEORDER))
    shake.update(msg)
    # Length is sufficient?
    c_hash = shake.read(param.target_bitsec // 8)
    return c_hash


def challenge_poly(param, c_hash):
    """
    Derive the challenge polynomial from the challenge hash .
    """

    # Fetch parameters
    n = param.n
    mask_n = (n - 1)
    logn = mask_n.bit_length()
    n = param.n
    omega = param.w
    assert(omega < n)
    # For each sample, we need logn bits for the position and 1 bit for the sign
    bytesread = ceil((logn + 1) / 8)

    # Initialize the SHAKE context
    shake = SHAKE256.new()
    shake.update(c_hash)

    # This is not the "usual" Fisher-Yates method as used in e.g. Dilithium
    # I expect this method to be simpler and more entropy-efficient.
    c_poly = [0] * n
    set = 0
    while(set < omega):
        rand_bytes = shake.read(bytesread)
        rand_int = int.from_bytes(rand_bytes, BYTEORDER)
        sign = rand_int & 1
        idx = (rand_int >> 1) & mask_n
        if (c_poly[idx] == 0):
            c_poly[idx] = (2 * sign - 1)
            set += 1
    return c_poly


def keygen(param):
    """
    Key generation of Raccoon.
    """
    # Unpack param
    # lq = param.lq
    # lqt = param.lqt
    lpt = param.lpt
    q = param.q
    qt = q >> lpt
    n = param.n
    k = param.k
    ell = param.ell
    bitsec = param.target_bitsec
    d = param.d

    # Generate public matrix A from A_seed
    A_seed = randbits(bitsec).to_bytes(bitsec // 8, BYTEORDER)
    A = expand_seed(param, A_seed)
    A_ntt = ntt_mat(A)

    # Generate masked secret vector ms = [[s]]

    # [debug] note: the original code didn't transform s
    #ms_ntt = random_mvec(ell, d, n, q)
    ms = random_mvec(ell, d, n, q)
    ms_ntt = ntt_mat(ms)

    # Compute public key syndrom [[t]] = A * [[s]]
    mt_ntt = mul_mat_mvec_ntt(A_ntt, ms_ntt, q)
    mt = intt_mvec(mt_ntt)

    # [debug]
    #debug_qsum("mt", mt)

    mt = orderswitch_mvec(mt, q)

    # [debug]
    #debug_qsum("mt2", mt)

    approxshift_mvec_inplace(mt, lpt, qt)

    # [debug]
    #debug_qsum("mt2'", mt)

    t = decode_mvec(mt, qt)

    # Pack and output the signing and verification keys.
    # (A_seed, t) are part of the secret key even if they are not secret.

    # [debug] note: the original code stored ms_ntt in msk
    # msk = (A_seed, t, ms_ntt)
    msk = (A_seed, t, ms)
    vk = (A_seed, t)
    return msk, vk


def sign(param, msk, msg):
    """
    Signing procedure of Raccoon.
    """

    # Unpack param and msk
    k = param.k
    ell = param.ell
    d = param.d
    n = param.n
    lpt = param.lpt
    lpw = param.lpw
    q = param.q
    qw = q >> lpw

    # [debug] note: the original code stored ms_ntt in msk
    # (A_seed, t, ms_ntt) = msk
    (A_seed, t, ms) = msk
    ms_ntt = ntt_mat(ms)

    # Expand the seed
    A = expand_seed(param, A_seed)
    A_ntt = ntt_mat(A)

    while(1):
        # Generate masked ephemeral randomness mr = [[r]]

        # [debug] note: the original code stored ms_ntt in msk
        # mr_ntt = random_mvec(ell, d, n, q)
        mr = random_mvec(ell, d, n, q)
        mr_ntt = ntt_mat(mr)

        # Compute and decode the commitment [[w]] = ApproxRound(A * [[r]]).
        mw_ntt = mul_mat_mvec_ntt(A_ntt, mr_ntt, q)
        mw = intt_mvec(mw_ntt)

        # [debug]
        refresh_mvec(mw, q)

        approxshift_mvec_inplace(mw, lpw, qw)
        w = decode_mvec(mw, qw)

        # Compute in clear the challenge c = H(w, msg).
        # As in Dilithium, this computation is split in two.
        c_hash = challenge_hash(param, msg, w)
        c_poly = challenge_poly(param, c_hash)
        c_ntt = ntt(c_poly)

        # Refresh the signing key and ephemeral secret
        refresh_mvec(msk[2], q)
        refresh_mvec(mr_ntt, q)

        # Compute and decode the response [[z]] = c * [[s]] + [[r]]
        # ms_ntt = ntt_mvec(ms)
        mz_ntt = mul_mvec_poly_ntt(ms_ntt, c_ntt, q)
        mz_ntt = add_mvec(mz_ntt, mr_ntt, q)
        z_ntt = decode_mvec(mz_ntt, q)
        z = intt_vec(z_ntt)

        # Compute in clear the hint h = w - y,
        # where y = round(A * z - p_t * c * t)
        y0_ntt = mul_mat_vec_ntt(A_ntt, z_ntt, q)
        y1 = leftshift_vec(t, lpt, q)
        y1_ntt = ntt_vec(y1)
        y1_ntt = mul_poly_vec_ntt(c_ntt, y1_ntt, q)

        y_ntt = sub_vec(y0_ntt, y1_ntt, q)
        y = intt_vec(y_ntt)
        shift_vec_inplace(y, qw, lpw)
        h = sub_vec(w, y, qw)
        center_vec(h, qw)

        # Check the squared-euclidean and infinity norms of h
        # The condition rsp_norms is True if and only h is small enough
        euclidean, infinity = compute_norms(h)
        rsp_norms = (euclidean <= param.B22) & (infinity <= param.Boo)

		# [Debug}
        #print("B22= ", euclidean, "  Boo= ", infinity)

        if (rsp_norms is True):
            # Pack and return signature
            sig = (c_hash, z, h)
            # encode_hint(h)
            return sig


def verify(param, vk, msg, sig):
    """
    Verification procedure of Raccoon.
    """
    # Unpacking param
    lpt = param.lpt
    lpw = param.lpw
    q = param.q
    qw = q >> lpw

    # Unpacking vk and sig
    (A_seed, t) = vk
    (c_hash, z, h) = sig

    # Compute a bunch of NTTs
    A = expand_seed(param, A_seed)
    c_poly = challenge_poly(param, c_hash)
    A_ntt = ntt_mat(A)
    c_ntt = ntt(c_poly)
    z_ntt = ntt_vec(z)

    # Recompute y
    y0_ntt = mul_mat_vec_ntt(A_ntt, z_ntt, q)
    y1 = leftshift_vec(t, lpt, q)
    y1_ntt = ntt_vec(y1)
    y1_ntt = mul_poly_vec_ntt(c_ntt, y1_ntt, q)
    y_ntt = sub_vec(y0_ntt, y1_ntt, q)
    y = intt_vec(y_ntt)
    shift_vec_inplace(y, qw, lpw)

    # Recompute the commitment w, then the challenge c_hash
    # The condition rsp_hash is True if and only if the hashes match
    w = add_vec(h, y, qw)
    c_hash_new = challenge_hash(param, msg, w)
    rsp_hash = (c_hash == c_hash_new)

    # Check the squared-euclidean and infinity norms of h
    # The condition rsp_norms is True if and only h is small enough
    euclidean, infinity = compute_norms(h)
    rsp_norms = (euclidean <= param.B22) & (infinity <= param.Boo)

    flat_h =  [x for elt in h for x in elt]
    mean = sum(flat_h) / len(flat_h)
    D = {key: flat_h.count(key) for key in set(flat_h)}
    D = dict(sorted(D.items()))
    # for key in D:
    #     print(str(key).ljust(4), D[key])
    # print(str(mean).ljust(20), euclidean, infinity)

    rsp = rsp_hash & rsp_norms
    return rsp

# creating header files

def print_param(param):
    macro = f'RACCOON_{param.target_bitsec}_{param.d}'
    print("#elif defined(", macro, ")" )
    print()
    print("#define RACC_SEC   ", param.target_bitsec // 8 )
    print("#define RACC_Q     ", param.q )
    print("#define RACC_LPT   ", param.lpt )
    print("#define RACC_LPW   ", param.lpw )
    print("#define RACC_N     ", param.n )
    print("#define RACC_K     ", param.k )
    print("#define RACC_ELL   ", param.ell )
    print("#define RACC_W     ", param.w )
    print("#define RACC_D     ", param.d )
    print("#define RACC_B22   ", param.B22 )
    print("#define RACC_BOO   ", param.Boo )
    print("#define RACC_CTT   ", get_corr_term(2*param.d, param.lpt) )
    print("#define RACC_CTW   ", get_corr_term(param.d, param.lpw) )
    print()

if (__name__ == "__main__"):
    # param = raccoon_toy
    param = raccoon_192

    for param in [
         # raccoon_128_2,
         # raccoon_128_4,
         # raccoon_128_8,
         # raccoon_128_16,
         raccoon_128_32,
         # raccoon_192_32,
         # raccoon_256_32,
        ]:


        print("=== KeyGen ===")
        fake_rand.__init__(1)

        start = timer()
        msk, vk = keygen(param)
        end = timer()
        msec = round((end - start) * 1000, 3)
        print("{msec} msec".format(msec=msec))

        (A_seed, t, ms) = msk
        print(f'A_seed: {A_seed.hex()}')
        debug_qsum("t", [t])
        debug_qsum("s", ms)

        print("=== Sign ===")
        fake_rand.__init__(2)

        msg = b"abc"
        start = timer()
        sig = sign(param, msk, msg)
        end = timer()
        msec = round((end - start) * 1000, 3)
        print("{msec} msec".format(msec=msec))

        (c_hash, z, h) = sig
        print(f'c_hash: {c_hash.hex()}')
        debug_qsum("z", [z])
        debug_qsum("h", [h])

        print("=== Verify ===")
        start = timer()
        rsp = verify(param, vk, msg, sig)
        end = timer()
        msec = round((end - start) * 1000, 3)
        print("Verification: ", rsp)
        print("{msec} msec".format(msec=msec))


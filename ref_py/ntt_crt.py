import constants.q_16515073 as cq1
import constants.q_33292289 as cq2

q1 = cq1.q
q2 = cq2.q

sqr1 =      {q1: cq1.sqr1,       q2: cq2.sqr1}
i2 =        {q1: cq1.i2,         q2: cq2.i2}
i2sqr1 =    {q1: cq1.i2sqr1,     q2: cq2.i2sqr1}
roots =     {q1: cq1.roots_dict, q2: cq2.roots_dict}

crt1 = 541233541287936
crt2 = 8591041884162


def split(f):
    """Split a polynomial f in two polynomials.
    Args:
        f: a polynomial
    Format: coefficient
    """
    f0 = f[0::2]
    f1 = f[1::2]
    return [f0, f1]


def merge(f_list):
    """Merge two polynomials into a single polynomial f.
    Args:
        f_list: a list of polynomials
    Format: coefficient
    """
    f0, f1 = f_list
    n = 2 * len(f0)
    f = [0] * n
    f[0::2] = f0
    f[1::2] = f1
    return f


def split_ntt(f_ntt, q):
    """Split a polynomial f in two or three polynomials.
    Args:
        f_ntt: a polynomial
    Format: NTT
    """
    n = len(f_ntt)
    n2 = n >> 1
    n4 = n >> 2
    w = roots[q][n]
    f0_ntt = [0] * n2
    f1_ntt = [0] * n2
    for i in range(n2):
        f0_ntt[i] = (i2[q] * (f_ntt[2 * i] + f_ntt[2 * i + 1])) % q
        f1_ntt[i] = (i2[q] * (f_ntt[2 * i] - f_ntt[2 * i + 1]) * w[i ^ n4]) % q
    return [f0_ntt, f1_ntt]


def merge_ntt(f_list_ntt, q):
    """Merge two or three polynomials into a single polynomial f.
    Args:
        f_list_ntt: a list of polynomials
    Format: NTT
    """
    f0_ntt, f1_ntt = f_list_ntt
    n = 2 * len(f0_ntt)
    w = roots[q][n]
    f_ntt = [0] * n
    for i in range(n // 2):
        f_ntt[2 * i + 0] = (f0_ntt[i] + w[i] * f1_ntt[i]) % q
        f_ntt[2 * i + 1] = (f0_ntt[i] - w[i] * f1_ntt[i]) % q
    return f_ntt


def ntt(f, q):
    """
    Compute the NTT of a polynomial.
    Args:
        f: a polynomial
    Format: input as coefficients, output as NTT
    """
    n = len(f)
    if (n > 2):
        f0, f1 = split(f)
        f0_ntt = ntt(f0, q)
        f1_ntt = ntt(f1, q)
        f_ntt = merge_ntt([f0_ntt, f1_ntt], q)
    elif (n == 2):
        f_ntt = [0] * 2
        f_ntt[0] = (f[0] + sqr1[q] * f[1]) % q
        f_ntt[1] = (f[0] - sqr1[q] * f[1]) % q
    return f_ntt


def intt(f_ntt, q):
    """
    Compute the inverse NTT of a polynomial.
    Args:
        f_ntt: a NTT of a polynomial
    Format: input as NTT, output as coefficients
    """
    n = len(f_ntt)
    if (n > 2):
        f0_ntt, f1_ntt = split_ntt(f_ntt, q)
        f0 = intt(f0_ntt, q)
        f1 = intt(f1_ntt, q)
        f = merge([f0, f1])
    elif (n == 2):
        f = [0] * n
        f[0] = ((f_ntt[0] + f_ntt[1]) * i2[q]) % q
        f[1] = ((f_ntt[0] - f_ntt[1]) * i2sqr1[q]) % q
    return f


def mul_ntt(f_ntt, g_ntt, q):
    """Multiplication of two polynomials (coefficient representation)."""
    assert len(f_ntt) == len(g_ntt)
    deg = len(f_ntt)
    return [(f_ntt[i] * g_ntt[i]) % q for i in range(deg)]


# def mul_zq(f, g, q):
#     """Multiplication of two polynomials (coefficient representation)."""
#     return intt(mul_ntt(ntt(f), ntt(g)))

def ntt_crt(f):
    f1 = [elt % q1 for elt in f]
    f2 = [elt % q2 for elt in f]
    f1_ntt = ntt(f1, q1)
    f2_ntt = ntt(f2, q2)
    return (f1_ntt, f2_ntt)


def mul_ntt_crt(f_ntt, g_ntt):
    return (mul_ntt(f_ntt[0], g_ntt[0], q1), mul_ntt(f_ntt[1], g_ntt[1], q2))


def intt_crt(f_ntt):
    q = q1 * q2
    f1 = intt(f_ntt[0], q1)
    f2 = intt(f_ntt[0], q2)
    return [(x * crt1 + y * crt2) % q for x, y in zip(f1, f2)]
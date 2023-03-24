"""
Deterministic non-cryptographic LCG for debug / test vectors.
"""

#   debug_rand.py

#   linear congurential generator: x' = (x + c) * g  (mod q)

#   q = 549824583172097
#   c = 314159265358979
#   g = 123456790123

class debug_rand:
    def __init__(self, seed = 0):
        self.x = seed

    def randq(self):
        self.x = ((self.x + 314159265358979) * 123456790123) % 549824583172097
        return self.x

    def getbyte(self):
        return self.randq() & 0xFF

    # a bytearray of given size

    def randombytes(self, n):
        return bytes([ self.getbyte() for i in range(n) ])

    # create a k-bit int

    def randbits(self, k):
        x = int.from_bytes( self.randombytes((k + 7) // 8), "little" )
        return x & ((1 << k) - 1)

    # random number [ 0, q-1 ]

    def randbelow(self, q):
        if q == 549824583172097:
            return self.randq()
        log_q = q.bit_length()
        x = self.randbits(log_q)
        while x >= q:
            x = self.randbits(log_q)
        return x

    def randvec(self, n, q):
        return [self.randbelow(q) for i in range(n)]


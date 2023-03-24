from ntt import q
from dataclasses import dataclass

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


############################
### 128 bits of security ###
############################

# Masking order d = 32
raccoon_128_32 = Param(target_bitsec=128, \
    q=q, lpt=10, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=(1 << 14), Boo=8, d=32)

# Masking order d = 16
raccoon_128_16 = Param(target_bitsec=128, \
    q=q, lpt=11, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=(1 << 13), Boo=6, d=16)

# Masking order d = 8
raccoon_128_8 = Param(target_bitsec=128, \
    q=q, lpt=11, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=(1 << 12), Boo=4, d=8)

# Masking order d = 4
raccoon_128_4 = Param(target_bitsec=128, \
    q=q, lpt=12, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=2500, Boo=3, d=4)

# Masking order d = 2
raccoon_128_2 = Param(target_bitsec=128, \
    q=q, lpt=12, lpw=43, \
    n=512, k=8, ell=3, w=19, B22=1500, Boo=1, d=2)


############################
### 192 bits of security ###
############################

# Masking order d = 32
raccoon_192_32 = Param(target_bitsec=192, \
    q=q, lpt=6, lpw=40, \
    n=512, k=11, ell=5, w=31, B22=(1 << 15), Boo=8, d=32)


############################
### 256 bits of security ###
############################

# Masking order d = 32
raccoon_256_32 = Param(target_bitsec=256, \
    q=q, lpt=7, lpw=42, \
    n=512, k=14, ell=6, w=44, B22=21000, Boo=8, d=32)
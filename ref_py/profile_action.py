"""
Profile the code with:
> make profile
"""
from raccoon import *

if __name__ == "__main__":
    param = raccoon_128_50
    print("Keygen")
    msk, vk = keygen(param)
    msg = b"abc"
    print("Sign")
    sig = sign(param, msk, msg)
    print("Verify")
    rsp = verify(param, vk, msg, sig)
    print(rsp)

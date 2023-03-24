# sp23-craccoon

2022-07-21	Raccoon Signature Developers

**WARNING!** This is purely a research artifact: C-language prototype of an early version of the Masked Raccoon signature scheme as described in the paper:

Rafaël del Pino, Thomas Prest, Mélissa Rossi, Markku-Juhani O. Saarinen:
_"High-Order Masking of Lattice Signatures in Quasilinear Time."_
Proc. 44th IEEE Symposium on Security and Privacy (IEEE S&P 2023)
https://sp2023.ieee-security.org/

##	Description

This prototype implementation is written in ANSI C for portability. It uses similar API conventions as those used in the NIST PQC Project algorithm evaluation. The NTT arithmetic is implemented using 64-bit Montgomery reduction. It has no external library dependencies, and platform-specific assembly optimization or SIMD intrinsics are not used. Constant-time implementation techniques are used. 

However, a portable implementation can’t have a real expectation of side-channel security. The purpose of CRACCOON is to serve as a reference and to evaluate the relative characteristics of Raccoon.

**ANOTHER WARNING!** This version only matches the IEEE S&P 2023 description; RACCOON has been further developed after the submission and publication of that article. This is a historical research artifact and should not be used for production use.


##	Structure of the implementation

Some shortcuts are taken; the main concern has been understanding of
the functional components of the scheme. It is clear that efficient masking
refresh is essential for this scheme; this is currently being studied.

*	`inc/*.h`: Include files for utilities (Keccak, constant-time, etc.)
*	`test/*`: CBMC scripting for proving Motgomery reduction bounds.
*	`raccoon.c`, `raccoon.h`: Main algorithm implementation.
*	`polyr.c`, `polyr.h`, `mont64.h`:
		Polynomial rings with 64-bit Montgomery reduction.
*	`ct_util.c`, `keccakf1600.c`, `plat_sha3.c`: Constant time helpers, SHA-3.
*	`test_main.c` simple test code.

##	Running it


The C code has no special library dependencies; it is self-contained.
On a Linux system, the command `make test` will build the test binary
`xtest` and run it. This gives some check values and speed measurements.

```
craccoon$ make test
[..]
./xtest
=== KeyGen ===
A_seed: 782dd329ed62f1a9b867dd773e4a9285
t[1][8][512]: 345972872951237
s[3][32][512]: 159827932868741
=== Sign ===
c_hash: 9ed0ee571cd2c82d3a9e5ddbc140fbfd
z[1][3][512]: 459920109001603
h[1][8][512]: 66722881794410
=== Verify ===
Verification: True
=== Check Main ===
Verification: True
=== Bench ===
Raccoon-128_32
	KeyGen()   256:    7.256 ms  13060444 cyc
	  Sign()   256:    6.319 ms  11374878 cyc
	 Verif()  2048:    0.578 ms   1040725 cyc
```

The same private key and signature values can be obtained with a 
slightly modified Raccoon python implementation at `ref_py/ref_py.py`.

This code uses the same simple linear congruential generator for
random mumbers, and doesn't sample some some quantities directly into
the NTT domain. This is necessary since the NTT representations differ
between the C code and the Python code (different roots of unity,
their ordering, and Montgomery reduction constants).

```
craccoon$ cd ref_py
craccoon/ref_py$ python3 ref_py.py 
=== KeyGen ===
[..] msec
A_seed: 782dd329ed62f1a9b867dd773e4a9285
t[1][8][512]: 345972872951237
s[3][32][512]: 159827932868741
=== Sign ===
[..] msec
c_hash: 9ed0ee571cd2c82d3a9e5ddbc140fbfd
z[1][3][512]: 459920109001603
h[1][8][512]: 66722881794410
=== Verify ===
Verification:  True
[..] msec
```


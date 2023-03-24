# pyRaccoon

This repository contains a Python implementation of Raccoon for a prime modulus q.

Raccoon is a masking-friendly signature scheme. In our case, this means:
* The key generation and signing procedures are performed in masked form (each sensitive value is split in d shares).
* The verification procedures is performed in unmasked form (there is no sensitive value).
Masking is performed at the polynomial level. This means a masked polynomial is stored as d polynomials, not as one single polynomial with masked coefficients.

## Content

This repository contains the following files (roughly in order of dependency):

1. [`ntt_constants.py`](ntt_constants.py) contains precomputed constants for the NTT over rings Z_q[x]/(x^n + 1) for q = 2^49 - 2^30 + 1.
1. [`ntt.py`](ntt.py) implements the NTT over rings Z_q[x]/(x^n + 1) for q = 2^49 - 2^30 + 1.
1. [`algebra.py`](algebra.py) contains basic procedures over polynomial rings and linear spaces over these rings.
1. [`masked_algebra.py`](masked_algebra.py) contains basic procedures over *masked* polynomial rings and linear spaces over these rings.
1. [`raccoon.py`](raccoon.py) implements the Raccoon signature scheme.
1. [`test.py`](test.py) implements tests to check that everything is properly implemented.
1. [`profile_action.py`](profile_action.py) is a tiny script for benchmarking purposes (instructions below).

## Taxonomy

Most arithmetic operations are performed over one of the following types (roughly in order of dependency):

* Polynomials over Z_q[x]/(x^n + 1), noted `poly`. These are the basic building blocs of our scheme, and are stored as lists of n integers in {0, ..., q - 1}.
* Vectors of polynomials, noted `vec`. These are stored as lists of `poly` elements (their length is usually noted k or ell).
* Matrices of polynomials, noted `mat`. These are stored as lists of lists of `poly` elements. The length of the outer (resp. inner) list is noted k (resp. ell), so that matrices have dimensions k * ell.
* *Masked* polynomials Z_q[x]/(x^n + 1), noted `mpoly`. These are stored as lists of d `poly` elements.
* *Masked* vectors, noted `mvec`. These are stored as lists of `mpoly` elements (their length is usually noted k or ell).

To improve readability, functions names are often suffixed by the types of the main inputs. For example, the function `mul_mvec_poly` performs multiplication of a `mvec` type with a `poly` type. Inplace functions also have the `_inplace` suffix.

## Profiling

I included a makefile target to performing profiling on the code. If you type `make profile` on a Linux machine, you should obtain something along these lines:

TODO: picture
![kcachegrind](images/kcachegrind.png)

Make sure you have `pyprof2calltree` and `kcachegrind` installed on your machine, or it will not work.


## Author

* **Thomas Prest** (thomas • prest ↺ pqshield • com)


## Disclaimer

This is experimental code. Please report errors to my email address.


## License

TODO

yescrypt
==========

[![Build Status](https://travis-ci.org/defuse/yescrypt.svg?branch=master)](https://travis-ci.org/defuse/yescrypt)

This repository holds my implementations of the yescrypt algorithm done for
Google Summer of Code 2015.

Documentation
---------------

Here are some useful yescrypt and scrypt links:

- [All Password Hashing Competition candidates](https://password-hashing.net/candidates.html)
- [The yescrypt specification](https://password-hashing.net/submissions/specs/yescrypt-v1.pdf)
- [The yescrypt C implementations](https://password-hashing.net/submissions/yescrypt-v1.tar.gz)
- [Colin Percival's scrypt paper](https://www.tarsnap.com/scrypt/scrypt.pdf)
- [The scrypt Internet-Draft](https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-02)

Optimization
---------------

Currently, none of the implementations are optimized.

Using a non-optimized implementation in production is a security weakness. This
is because you are forced to use weaker parameters than you could have with an
optimized implementation, and therefore the attacker has more of an advantage.

Use an optimized native implementation if possible.

Audit Status
---------------

None of the code in this repository has been professionally reviewed. The code
here should be considered experimental and not used in production until this
notice is removed.

Reporting Security Bugs
-------------------------

Please disclose bugs publicly by opening an issue on GitHub. If you need to
disclose privately for some reason, or don't have a GitHub account, you can find
my contact information [here](https://defuse.ca/contact.htm).

The `ecmascript_simd` polyfill
--------------------------------

The polyfill for SIMD operations, in `javascript/ecmascript_simd.js`, was taken
from [tc38/ecmascript_simd](https://github.com/tc39/ecmascript_simd/) and
modified to support `shiftRightLogicalByScalar` on `Int32x4`.

Common API
----------

Each of the yescrypt implementations provides the following command-line API:

```
yescrypt-cli <function> <args...>
```

Here, `<function>` can be one of the following:

- `yescrypt`: Compute the `yescrypt` function using arguments `password` (hex
  encoded), `salt` (hex encoded), `N`, `r`, `p`, `t`, `g`, `flags`, and `dkLen`
  in that order.

- `pwxform`: Compute the `pwxform` function on the arguments `pwxblock` (hex
  encoded) and `sbox` (hex encoded) in that order.

- `salsa20_8`: Compute the salsa20 function reduced to 8 rounds on the
  hex-encoded cell provided as the next argument.

- `benchmark`: Run a performance benchmark (see below for arguments.).

When `<function>` is `benchmark`, the next argument is the iteration count, and
then further arguments can be:

- `yescrypt`: Benchmark the yescrypt function, with the following arguments
  being `N`, `r`, `p`, `t`, `g`, `flags`, and `dkLen` in that order, printing
  the performance of computing yescypt with those parameters on random
  passphrases and salts in c/s.

- `pwxform`: Benchmark the `pwxform` function on a random block and sbox,
  printing the result in c/s.

- `salsa20_8`: Benchmark the `salsa20_8` function on a random cell, printing the
  result in c/s.

Each implementation is expected to report its average performance for that many
iterations of the requested function. Implementations should strive to return as
accurate results as possible. If no meaningful accuracy is possible given the
provided iteration count, the benchmark command may fail with an error message.

The rationale for making each implementation have their own timing code is that
firstly, the overhead of process creation, etc. is not included in the running
time, and secondly, that each language "knows best" how to benchmark itself.

The rationale for not letting implementations decide the iteration count for
themselves is that the benchmark user is the one who decides how long they want
to run the benchmarks for and what kind of accuracy they expect.

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

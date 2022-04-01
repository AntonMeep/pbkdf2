pbkdf2
[![License](https://img.shields.io/github/license/AntonMeep/pbkdf2.svg?color=blue)](https://github.com/AntonMeep/pbkdf2/blob/master/LICENSE.txt)
[![Alire crate](https://img.shields.io/endpoint?url=https://alire.ada.dev/badges/pbkdf2.json)](https://alire.ada.dev/crates/pbkdf2.html)
[![GitHub release](https://img.shields.io/github/release/AntonMeep/pbkdf2.svg)](https://github.com/AntonMeep/pbkdf2/releases/latest)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/AntonMeep/pbkdf2/Default)](https://github.com/AntonMeep/pbkdf2/actions)
=======

This is a PBKDF2 algorithm implemented in Ada, tested against RFC6070 test
vectors. Currently PBKDF2_HMAC_SHA_1, PBKDF2_HMAC_SHA_256 and PBKDF2_HMAC_SHA_512
are implemented using respective hmac, sha{1,2} crates. It is easy to use the
generic interface to define new PBKDF2 functions for other hash functions.

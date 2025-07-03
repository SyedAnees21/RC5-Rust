# RC5-CLI

A command‑line utility for encrypting and decrypting files or data streams using the RC5 block cipher. This tool is built
in rust using the [rc5-rs](./README.md) a rust lib. This tool can be compiled for different word sizes can compile time and
can operate in different operation modes.


Supports variable word sizes (`16`, `32`, `64`‑bit), and the classic modes **ECB**, **CBC**, and **CTR** with PKCS#7 padding (where required).

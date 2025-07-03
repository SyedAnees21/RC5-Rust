# rc5-rs

[![crates.io](https://img.shields.io/crates/v/rc5-rs.svg)](https://crates.io/crates/rc5-rs)  
[![docs.rs](https://docs.rs/rc5-rs/badge.svg)](https://docs.rs/rc5-rs)  
[![license](https://img.shields.io/crates/l/rc5-rs.svg)](./LICENSE)

A pure‑Rust implementation of the RC5 block cipher, supporting variable word‑sizes (`u16`, `u32`, `u64`, `u128`),  
PKCS#7 padding and the three classic modes of operation: **ECB**, **CBC**, and **CTR**.

This implementation is inspired by the original paper on [RC5-Block-Cipher](https://www.grc.com/r&d/rc5.pdf) by
Ronald L. Rivest.

---

## Features

This library is generic over word-size per block and suppoerts multiple operation modes.

- **Supported Word sizes**:  
  - 16‑bit  
  - 32‑bit   
  - 64‑bit 
  - 128 bit 

- **Modes**  
  - **ECB**: Electronic Codebook  
  - **CBC**: Cipher Block Chaining (with PKCS#7 padding)  
  - **CTR**: Counter mode (no padding)

- **Helpers**  
  - PKCS#7 padding/unpadding  (Strict)
  - Random IV / nonce+counter generators  
  - Parse hex strings for IV and nonce  

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rc5-rs = "0.1"
```

And start using it in your application

```rust
use rc5_rs::{
    rc5_cipher,                     // builder
    OperationMode,                  // enum for mode
    random_iv,                      // for CBC
    random_nonce_and_counter,       // for CTR
    utils::pkcs7,                   // padding helper
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Build an RC5 cipher: 32‑bit words, 12 rounds
    let cipher = rc5_cipher::<u32>("my secret key", 12)?;

    let plaintext = b"The quick brown fox jumps over the lazy dog";

    // --- ECB ---
    let ct_ecb = cipher.encrypt(plaintext, OperationMode::ECB)?;
    let pt_ecb = cipher.decrypt(&ct_ecb, OperationMode::ECB)?;
    assert_eq!(pt_ecb, plaintext);

    // --- CBC ---
    let iv = random_iv::<u32, 2>();
    let ct_cbc = cipher.encrypt(plaintext, OperationMode::CBC { iv })?;
    let pt_cbc = cipher.decrypt(&ct_cbc, OperationMode::CBC { iv })?;
    assert_eq!(pt_cbc, plaintext);

    // --- CTR ---
    let nc = random_nonce_and_counter::<u32, 2>();
    let ct_ctr = cipher.encrypt(plaintext, OperationMode::CTR { nonce_and_counter: nc })?;
    // CTR decryption is same call:
    let pt_ctr = cipher.decrypt(&ct_ctr, OperationMode::CTR { nonce_and_counter: nc })?;
    assert_eq!(pt_ctr, plaintext);

    Ok(())
}
```

## Testing

This library is tested against some of the standard test vectors and round trip tests. These tests are define [here](./rc5-rs/src/tests/).
Standard test vector are picked from [here](https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Rc5-128-64.verified.test-vectors).

---

## RC5-CLI

This is a command-line application developed using this library, see it [readme](./rc5-cli/README.md) for more.
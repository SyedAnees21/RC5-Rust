//! # RC5-RS Cipher Library
//!
//! This crate provides a generic, parametric implementation of the RC5 block cipher,
//! supporting variable word sizes (`u16`, `u32`, `u64`) and multiple modes of operation
//! (ECB, CBC, CTR). It includes PKCS#7 padding helpers, IV/nonce generators, and
//! convenient parsing of hex‐encoded parameters.
//!
//! ## Features
//!
//! - Variable word length: `16-bit`, `32-bit`, `64-bit`.
//! - Various operation modes:
//!     - ECB
//!     - CBC
//!     - CTR
//! - Strict padding using PKCS#7 standard.
//! - Pseudo-random IV/nonce generation utitlities , see [random_iv], [random_nonce_and_counter].
//! - Hex‐string parsing for IVs and nonces.
//!
//! ## Example
//!
//! ```rust
//! use rc5_block::{rc5_cipher, OperationMode};
//!
//! // Build a 32‐bit word RC5 cipher with 12 rounds:
//! let cipher = rc5_cipher::<u32>(b"mykey", 12).unwrap();
//!
//! let plaintext = b"Secret message";
//!
//! // Encrypt in CBC mode with a random IV:
//! let iv = rc5_block::random_iv::<u32, 2>();
//! let ciphertext = cipher.encrypt(plaintext, OperationMode::CBC { iv }).unwrap();
//!
//! // Decrypt using the same IV:
//! let recovered = cipher.decrypt(&ciphertext, OperationMode::CBC { iv }).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # Utilities
//!
//! This crate provide some extra utilities such as, pseudo-random iv and nonce
//! generation and PKCS#7 padding function:
//!
//! ```rust
//! // generate a pseudo-random iv-block of block size [u32;2]
//! let iv = rc5_block::random_iv::<u32, 2>();
//!
//! // generate a pseudo-random nonce and counter initialized to zero
//! // of block size [u32;2]
//! // Note: Higher part of this block conatins nonce and lower part
//! // contains counter with initial value set to zero.
//! let nonce_counter = rc5_block::random_nonce_and_counter::<u32, 2>();
//! ```
use hex::FromHexError;
use std::marker::PhantomData;
use thiserror::Error;

pub use crate::{
    modes::OperationMode,
    rc5::RC5ControlBlock,
    types::{Version, Word},
    utils::{pkcs7, random_iv, random_nonce_and_counter},
};

mod modes;
mod rc5;
mod types;
mod utils;

#[cfg(test)]
mod tests;

/// Errors returned by the Cipher as reasons during
/// cipher operations.
#[derive(Error, Debug)]
pub enum Reason {
    #[error("[RC5-Error] Word size mis-match")]
    WordSize,
    #[error("[RC5-Error] Invalid PKCS7 padding shceme")]
    Padding,
    #[error("[RC5-Error] RC5 key is too long, supported: {supported:?} max, current: {current:?}")]
    KeyTooLong { current: usize, supported: usize },
    #[error("[RC5-Error] Invalid RC5-key, received an empty key")]
    InvalidKey,
    #[error("[RC5-Error] Rounds out-of-bounds, must be within 0-255, current{0}")]
    InvalidRounds(usize),
    #[error("[RC5-Error] Unable to parse Hex-String {0}")]
    ParseHex(#[from] FromHexError),
    #[error("[RC5-Error] IV hex string should be equal to block size {0} bytes")]
    IVinvalid(usize),
    #[error("[RC5-Error] Nonce/Counter hex string should be equal to word-size {0} bytes")]
    NonceInvalid(usize),
}

/// # Cipher
///
/// A high‐level cipher wrapper type that contains a control block
/// It provides byte‐stream handling and cryptographic operation
/// modes dispatch.
///
/// ## Generics
///
/// - `B`: Control-Block, e.g. [`RC5ControlBlock<W>`].
/// - `W`: Underlying type which implements a [Word] trait.
/// - `N`: number of words per block (for RC5, always 2).
///
pub struct Cipher<B, W, const N: usize>
where
    W: Word,
    B: BlockCipher<W, N>,
{
    block: B,
    _marker: PhantomData<W>,
}

impl<B, W, const N: usize> Cipher<B, W, N>
where
    W: Word,
    B: BlockCipher<W, N>,
{
    /// Create a new `Cipher` wrapping the given block‐cipher instance.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use rc5_block::{RC5ControlBlock, Cipher};
    ///
    /// let rc5_control_block = RC5ControlBlock::<u32>::new("SECRET_KEY", 12).unwrap();
    /// let cipher = Cipher::new(rc5_control_block);
    /// ```
    pub fn new(block: B) -> Self {
        Self {
            block,
            _marker: PhantomData,
        }
    }

    /// Encrypt plain-text bytes under selected cryptographic operation mode
    /// and returns cipher-text bytes.
    ///
    /// This takes the plain-text as their bytes reference. It supports various
    /// encryption flows based on operation modes such as:
    ///
    /// - `ECB` : Electronic-code-book mode.
    /// - `CBC` : Cipher-block-chain mode.
    /// - `CTR` : Counter mode.
    ///
    /// Encryption might fail for various reasons, either due to padding or etc,
    /// that's why this function is fallible.
    ///
    /// It returns ciphered bytes, or [Reason] of failure as an err.
    pub fn encrypt(&self, pt: &[u8], mode: OperationMode<W, N>) -> Result<Vec<u8>, Reason> {
        let mut pt = pt.to_vec();

        match mode {
            modes::OperationMode::ECB => {
                let bs = self.block.block_size();
                utils::pkcs7(&mut pt, bs, true)?;
                let pt_blocks = self.block.generate_blocks(pt);
                let ct_blocks = modes::ecb_encrypt(&self.block, pt_blocks);

                Ok(self.block.generate_bytes_stream(ct_blocks))
            }
            modes::OperationMode::CBC { iv } => {
                let bs = self.block.block_size();
                utils::pkcs7(&mut pt, bs, true)?;
                let pt_blocks = self.block.generate_blocks(pt);
                let ct_blocks = modes::cbc_encrypt(&self.block, iv, pt_blocks);

                Ok(self.block.generate_bytes_stream(ct_blocks))
            }
            modes::OperationMode::CTR { nonce_and_counter } => {
                Ok(modes::ctr_encrypt(&self.block, nonce_and_counter, &pt))
            }
        }
    }

    /// Decrypt cipher-text bytes under selected cryptographic operation mode
    /// and returns plain-text bytes.
    ///
    /// This takes the plain-text as their bytes reference. It supports various
    /// encryption flows based on operation modes such as:
    ///
    /// - `ECB` : Electronic-code-book mode.
    /// - `CBC` : Cipher-block-chain mode.
    /// - `CTR` : Counter mode.
    ///
    /// Decryption might fail for various reasons, either due to padding or etc,
    /// that's why this function is fallible.
    ///
    /// It returns plain bytes, or [Reason] of failure as an err.
    pub fn decrypt(&self, ct: &[u8], mode: OperationMode<W, N>) -> Result<Vec<u8>, Reason> {
        let ct = ct.to_vec();

        let deciphered_bytes = match mode {
            OperationMode::ECB => {
                let ct_blocks = self.block.generate_blocks(ct);

                let bs = self.block.block_size();
                let pt_blocks = modes::ecb_decrypt(&self.block, ct_blocks);
                let mut pt_bytes = self.block.generate_bytes_stream(pt_blocks);
                utils::pkcs7(&mut pt_bytes, bs, false)?;

                pt_bytes
            }
            OperationMode::CBC { iv } => {
                let ct_blocks = self.block.generate_blocks(ct);

                let bs = self.block.block_size();
                let pt_blocks = modes::cbc_decrypt(&self.block, iv, ct_blocks);
                let mut pt_bytes = self.block.generate_bytes_stream(pt_blocks);
                utils::pkcs7(&mut pt_bytes, bs, false)?;

                pt_bytes
            }
            OperationMode::CTR { nonce_and_counter } => {
                modes::ctr_decrypt(&self.block, nonce_and_counter, &ct)
            }
        };

        Ok(deciphered_bytes)
    }

    /// Parse an IV from a hex‐encoded string, validating length = block size.
    /// Parsing may fail if the hex-string is not equal to blcok size.
    ///
    /// Returns a result contain iv block or failure reason as an err.
    pub fn parse_iv_from_hex<V>(&self, iv_hex: V) -> Result<[W; N], Reason>
    where
        V: AsRef<[u8]>,
    {
        let iv_bytes = hex::decode(iv_hex)?;
        let bs = self.control_block().block_size();
        bail!(iv_bytes.len() != bs, Reason::IVinvalid(bs));

        Ok(*self
            .control_block()
            .generate_blocks(iv_bytes)
            .last()
            .unwrap())
    }

    /// Parses nonce and counter from their respective
    /// hex-encoded strings.
    ///
    /// Parse may fail if the hex-string is not equal to
    /// word-size.
    pub fn parse_nonce_counter_from_hex<V>(
        &self,
        nonce_hex: V,
        counter_hex: V,
    ) -> Result<[W; N], Reason>
    where
        V: AsRef<[u8]>,
    {
        let mut nonce_bytes = hex::decode(nonce_hex)?;
        let counter_bytes = hex::decode(counter_hex)?;
        let ws = self.control_block().word_size();

        bail!(
            nonce_bytes.len() != ws && counter_bytes.len() != ws,
            Reason::NonceInvalid(ws)
        );
        nonce_bytes.extend_from_slice(&counter_bytes);

        Ok(*self
            .control_block()
            .generate_blocks(nonce_bytes)
            .last()
            .unwrap())
    }

    /// Returns an immutable access to control-block of block-cipher
    /// underlying the cipher.
    pub fn control_block(&self) -> &B {
        &self.block
    }
}

/// A core trait that any block-cipher must implement to work with [Cipher].
///
/// Generics in this trait defines:
///
/// - `W`: A variable length unit type which implements [Word] trait.
/// - `N`: A generic constand for number of words per block.
///
/// This trait coerces some of the necessary functionalities for block-cipher.  
pub trait BlockCipher<W: Word, const N: usize> {
    /// Human‐readable version tag, mostly a parametric version.
    /// e.g. in RC5-block-cipher  “RC5-32/12/16”.
    fn control_block_version(&self) -> String;

    /// Base block-size in bytes for a block-cipher.
    fn block_size(&self) -> usize;

    /// Word-szie in bytes per block for a block-cipher.
    fn word_size(&self) -> usize;

    /// Split a byte‐vector into a `Vec` of length-`N` word blocks.
    /// More generally, it creates a list of blocks from a stream of
    /// plain bytes.
    fn generate_blocks(&self, pt: Vec<u8>) -> Vec<[W; N]>;

    /// Generates a stream of bytes from a list of blocks. More
    /// specefically from `N` word blocks list generates byte-vector.
    /// Its counterfiet of generate_blocks method.
    fn generate_bytes_stream(&self, blocks: Vec<[W; N]>) -> Vec<u8>;

    /// Raw encryption, encrypt a single `[W;N]` block.
    ///
    /// Returns a cipher `[W;N]` block
    fn encrypt(&self, pt: [W; N]) -> [W; N];

    /// Raw decryption, decrypt a single `[W;N]` block.
    ///
    /// Returns a plain-text `[W;N]` block
    fn decrypt(&self, ct: [W; N]) -> [W; N];
}

pub type RC5Cipher<W> = Cipher<RC5ControlBlock<W>, W, 2>;

/// Construct a new RC5 cipher from a raw key and round count.
///
/// This is a help function which initializes Cipher with RC5
/// control-bock.
pub fn rc5_cipher<W>(key: impl AsRef<[u8]>, rounds: usize) -> Result<RC5Cipher<W>, Reason>
where
    W: Word,
{
    let control_block = RC5ControlBlock::<W>::new(key, rounds)?;
    Ok(Cipher::new(control_block))
}

/// Helper macro to bail out early with a `Reason` error
/// if any condition is true.
#[macro_export]
macro_rules! bail {
    ($expression:expr, $err:expr) => {
        if $expression {
            return Err($err);
        }
    };
    ( $( $cond:expr , $err:expr ),+ $(,)? ) => {
        $(
            if $cond {
                return Err($err);
            }
        )+
    };
}

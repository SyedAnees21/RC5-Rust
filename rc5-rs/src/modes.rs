use crate::{BlockCipher, Word};

/// Modes of operation for a block cipher.
///
/// - **ECB**: Electronic Codebook mode.  
/// - **CBC**: Cipher Block Chaining mode.  
/// - **CTR**: Counter mode.
///
/// ECB mode of operation is less secure and is not recommended
/// to use in production applications since it can be broken
/// muc easily, special care should be kept while using this
/// mode.
pub enum OperationMode<W: Word, const N: usize> {
    /// Electronic Codebook
    ///
    /// Encrypt/Decrypt each block independently Without any
    /// additional security.
    ECB,

    /// Cipher Block Chaining
    ///
    /// Requires an initialization vector to add one stage
    /// enhanced security.
    CBC { iv: [W; N] },

    /// Counter
    ///
    /// Requires a starting nonce + counter block, this way
    /// it adds two stage complexity over encryption/decryption.
    CTR { nonce_and_counter: [W; N] },
}

/// Encrypt a sequence of blocks in ECB mode.
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `input_blocks`: vector of full `[W; N]` plaintext blocks.
///
/// # Returns
/// A vector of `[W; N]` ciphertext blocks.
pub fn ecb_encrypt<C, W, const N: usize>(
    control_block: &C,
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    input_blocks
        .iter()
        .map(|block| control_block.encrypt(*block))
        .collect()
}

/// Decrypt a sequence of blocks in ECB mode.
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `input_blocks`: vector of full `[W; N]` ciphertext blocks.
///
/// # Returns
/// A vector of `[W; N]` plaintext blocks.
pub fn ecb_decrypt<C, W, const N: usize>(
    control_block: &C,
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    input_blocks
        .iter()
        .map(|block| control_block.decrypt(*block))
        .collect()
}

/// Encrypt in CBC mode.
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `iv`: Initialization Vector (`[W; N]`).  
/// - `input_blocks`: vector of full `[W; N]` plaintext blocks.
///
/// # Returns
/// A vector of `[W; N]` ciphertext blocks.
pub fn cbc_encrypt<C, W, const N: usize>(
    control_block: &C,
    iv: [W; N],
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    let mut prev = iv;

    input_blocks
        .iter()
        .map(|block| {
            prev.iter_mut()
                .enumerate()
                .for_each(|(ix, word)| *word = *word ^ block[ix]);
            let ct = control_block.encrypt(prev);
            prev = ct;

            ct
        })
        .collect()
}

/// Decrypt in CBC mode.
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `iv`: Initialization Vector (`[W; N]`).  
/// - `input_blocks`: vector of full `[W; N]` ciphertext blocks.
///
/// # Returns
/// A vector of `[W; N]` plaintext blocks.
pub fn cbc_decrypt<C, W, const N: usize>(
    control_block: &C,
    iv: [W; N],
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    let mut prev = iv;

    input_blocks
        .iter()
        .map(|block| {
            let mut decrypted = control_block.decrypt(*block);
            prev.iter_mut()
                .enumerate()
                .for_each(|(ix, word)| decrypted[ix] = decrypted[ix] ^ *word);

            prev = *block;
            decrypted
        })
        .collect()
}

/// Encrypt a byte stream in CTR mode (stream cipher).
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `nonce_and_counter`: initial counter block (`[W; N]`).  
/// - `input_stream`: plaintext bytes to encrypt (any length).
///
/// # Returns
/// A `Vec<u8>` ciphertext stream, same length as input.
pub fn ctr_encrypt<C, W, const N: usize>(
    control_block: &C,
    mut nonce_and_counter: [W; N],
    input_stream: &[u8],
) -> Vec<u8>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    let mut ciphered_stream = vec![];

    for input_chunk in input_stream.chunks(control_block.block_size()) {
        let encrypted = control_block.encrypt(nonce_and_counter);
        let key_stream = encrypted
            .iter()
            .flat_map(|word| word.to_bytes_slice())
            .collect::<Vec<_>>();

        for (ix, input) in input_chunk.iter().enumerate() {
            ciphered_stream.push(*input ^ key_stream[ix]);
        }
        nonce_and_counter[N - 1] = nonce_and_counter[N - 1].wrapping_add(W::from_u8(1));
    }
    ciphered_stream
}

/// Decrypt a byte stream in CTR mode (identical to encryption).
///
/// # Parameters
/// - `control_block`: the underlying block cipher instance.  
/// - `nonce_and_counter`: same initial counter block used in encryption.  
/// - `input_stream`: ciphertext bytes to decrypt (any length).
///
/// # Returns
/// A `Vec<u8>` plaintext stream.
pub fn ctr_decrypt<C, W, const N: usize>(
    control_block: &C,
    nonce_and_counter: [W; N],
    input_blocks: &[u8],
) -> Vec<u8>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    // Counter mode decryption is vice versa of counter mode encryption.
    // A cipher text can be decrypted by reeating the encryption with same
    // parameter configs.
    ctr_encrypt(control_block, nonce_and_counter, input_blocks)
}

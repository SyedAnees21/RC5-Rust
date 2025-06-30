use std::iter::Enumerate;

use crate::{BlockCipher, Word};

pub enum OperationMode<W: Word, const N: usize> {
    ECB,
    CBC { iv: [W; N] },
    CTR { nonce_and_counter: [W; N] },
}

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

pub fn ctr_decrypt<C, W, const N: usize>(
    control_block: &C,
    nonce_and_counter: [W; N],
    input_blocks: &[u8],
) -> Vec<u8>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    ctr_encrypt(control_block, nonce_and_counter, input_blocks)
}

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
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    input_blocks
        .into_iter()
        .map(|input_block| {
            let mut encrypted = control_block.encrypt(nonce_and_counter);
            encrypted
                .iter_mut()
                .enumerate()
                .for_each(|(ix, block)| *block = input_block[ix] ^ *block);

            nonce_and_counter[N - 1] = nonce_and_counter[N - 1].wrapping_add(W::from_u8(1));
            encrypted
        })
        .collect()
}

pub fn ctr_decrypt<C, W, const N: usize>(
    control_block: &C,
    mut nonce_and_counter: [W; N],
    input_blocks: Vec<[W; N]>,
) -> Vec<[W; N]>
where
    C: BlockCipher<W, N>,
    W: Word,
{
    input_blocks
        .into_iter()
        .map(|input_block| {
            let mut decrypted = control_block.decrypt(nonce_and_counter);
            decrypted
                .iter_mut()
                .enumerate()
                .for_each(|(ix, block)| *block = input_block[ix] ^ *block);

            nonce_and_counter[N - 1] = nonce_and_counter[N - 1].wrapping_add(W::from_u8(1));
            decrypted
        })
        .collect()
}
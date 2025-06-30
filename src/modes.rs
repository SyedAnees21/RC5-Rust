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
        .collect::<Vec<_>>()
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
        .collect::<Vec<_>>()
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
        .collect::<Vec<_>>()
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
        .collect::<Vec<_>>()
}

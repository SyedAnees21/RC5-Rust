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

#[derive(Error, Debug)]
pub enum Reason {
    #[error("Word size mis-match")]
    WordSize,
    #[error("Invalid PKCS7 padding shceme")]
    Padding,
    #[error("RC5 key is too long, supported: {supported:?} max, current: {current:?}")]
    KeyTooLong { current: usize, supported: usize },
    #[error("Invalid RC5-key, received an empty key")]
    InvalidKey,
}

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
    pub fn new(block: B) -> Self {
        Self {
            block,
            _marker: PhantomData,
        }
    }

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
}

pub trait BlockCipher<W: Word, const N: usize> {
    fn block_size(&self) -> usize;
    fn generate_blocks(&self, pt: Vec<u8>) -> Vec<[W; N]>;
    fn generate_bytes_stream(&self, blocks: Vec<[W; N]>) -> Vec<u8>;
    fn encrypt(&self, pt: [W; N]) -> [W; N];
    fn decrypt(&self, ct: [W; N]) -> [W; N];
}

pub type RC5Cipher<W> = Cipher<RC5ControlBlock<W>, W, 2>;

pub fn rc5_cipher<W>(key: impl AsRef<[u8]>, rounds: usize) -> Result<RC5Cipher<W>, Reason>
where
    W: Word,
{
    let control_block = RC5ControlBlock::<W>::new(key, rounds)?;
    Ok(Cipher::new(control_block))
}

#[macro_export]
macro_rules! bail {
    ($expression:expr, $err:expr) => {
        if !$expression {
            return Err($err);
        }
    };
}

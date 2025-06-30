use std::{marker::PhantomData, mem::MaybeUninit};

use rand::Rng;

pub use crate::{
    rc5::RC5ControlBlock,
    types::{IntoBytes, Version, Word},
    utils::{pkcs7, random_iv},
};

mod modes;
mod rc5;
mod types;
mod utils;

#[derive(Debug)]
pub enum Reason {
    WordSize,
    Padding(String),
}

pub enum OperationMode<W: Word, const N: usize> {
    ECB,
    CBC { iv: [W; N] },
    CTR { nonce_and_counter: [W; N] },
}

pub struct Cipher<B, W: Word, const N: usize>
where
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

        let ct_blocks = match mode {
            OperationMode::ECB => {
                let bs = self.block.block_size();
                utils::pkcs7(&mut pt, bs, true)?;
                let pt_blocks = self.block.generate_blocks(pt);
                modes::ecb_encrypt(&self.block, pt_blocks)
            }
            OperationMode::CBC { iv } => {
                let bs = self.block.block_size();
                utils::pkcs7(&mut pt, bs, true)?;
                let pt_blocks = self.block.generate_blocks(pt);
                modes::cbc_encrypt(&self.block, iv, pt_blocks)
            }
            OperationMode::CTR { nonce_and_counter } => unimplemented!("Yet to be implemented"),
        };

        Ok(self.block.generate_bytes_stream(ct_blocks))
    }

    pub fn decrypt(&self, ct: &[u8], mode: OperationMode<W, N>) -> Result<Vec<u8>, Reason> {
        let ct = ct.to_vec();

        match mode {
            OperationMode::ECB => {
                let bs = self.block.block_size();
                let ct_blocks = self.block.generate_blocks(ct);
                let pt_blocks = modes::ecb_decrypt(&self.block, ct_blocks);
                let mut pt_bytes = self.block.generate_bytes_stream(pt_blocks);
                utils::pkcs7(&mut pt_bytes, bs, false)?;

                Ok(pt_bytes)
            }
            OperationMode::CBC { iv } => {
                let bs = self.block.block_size();
                let ct_blocks = self.block.generate_blocks(ct);
                let pt_blocks = modes::cbc_decrypt(&self.block, iv, ct_blocks);
                let mut pt_bytes = self.block.generate_bytes_stream(pt_blocks);
                utils::pkcs7(&mut pt_bytes, bs, false)?;

                Ok(pt_bytes)
            }
            OperationMode::CTR { nonce_and_counter } => unimplemented!("Yet to be implemented"),
        }
    }
}

pub trait BlockCipher<W: Word, const N: usize> {
    fn block_size(&self) -> usize;
    fn generate_blocks(&self, pt: Vec<u8>) -> Vec<[W; N]>;
    fn generate_bytes_stream(&self, blocks: Vec<[W; N]>) -> Vec<u8>;
    fn encrypt(&self, pt: [W; N]) -> [W; N];
    fn decrypt(&self, ct: [W; N]) -> [W; N];
}

pub fn rc5_cipher<W>(key: impl IntoBytes, rounds: usize) -> Cipher<RC5ControlBlock<W>, W, 2>
where
    W: Word,
{
    let control_block = RC5ControlBlock::<W>::new(key, rounds);
    Cipher::new(control_block)
}

#[cfg(test)]
mod tests {
    use crate::{
        BlockCipher, Cipher,
        rc5::{self, RC5ControlBlock},
        rc5_cipher,
        utils::random_iv,
    };

    #[test]
    fn encrypt_word_32() {
        let key = vec![2_u8; 16];
        let pt = [0_u32; 2];
        let rounds = 12;

        let rc5 = RC5ControlBlock::<u32>::new(key, rounds);
        let cipher = rc5.encrypt(pt);
        println!("Cipher: {:?}", cipher);

        let text = rc5.decrypt(cipher);

        println!("{:#010x?}", pt);
        println!("{:#010x?}", text);

        println!("{}", rc5.parametric_version())
    }

    #[test]
    fn rc5_cipher_contructor() {
        use crate::{Word, rc5_cipher};

        let key = vec![2_u8; 16];
        let rounds = 12;

        let cipher = rc5_cipher::<u32>(key, rounds);

        let pt = b"Anees UR";

        let ct = cipher.encrypt(pt, crate::OperationMode::ECB).unwrap();

        dbg!(ct.len(), ct.clone());

        let de_pt = cipher
            .decrypt(ct.as_ref(), crate::OperationMode::ECB)
            .unwrap();

        dbg!(str::from_utf8(&de_pt));
    }

    #[test]
    fn rc5_cbc_test() {
        let key = [0_u8; 16];
        let rounds = 12;
        let cipher = rc5_cipher::<u32>(key.to_vec(), rounds);
        let random_iv = random_iv();

        let pt = b"Syed Anees Ur Rehman";
        let ct = cipher.encrypt(pt, crate::OperationMode::ECB).unwrap();
        dbg!(&ct);

        let d = cipher.decrypt(&ct, crate::OperationMode::ECB).unwrap();
        dbg!(str::from_utf8(&d));

        let ct = cipher
            .encrypt(
                b"This is my cipher!!",
                crate::OperationMode::CBC { iv: random_iv },
            )
            .unwrap();
        dbg!(String::from_utf8_lossy(&ct));
        dbg!(String::from_utf8_lossy(
            &cipher
                .decrypt(&ct, crate::OperationMode::CBC { iv: random_iv })
                .unwrap()
        ));
    }
}

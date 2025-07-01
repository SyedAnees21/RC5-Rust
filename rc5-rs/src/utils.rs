use std::array::from_fn;

use rand::thread_rng;

use crate::{Reason, Word, bail};

/// Generate a pseudo‑random IV (Initialization-Vector) of `[W; N]`.
///
/// # Requirements
///
/// - `W` must implement your `Word` trait + `Copy`
/// - `W` must also support `rand::distributions::Standard`
///
/// # Example
///
/// ```ignore
/// let iv: [u32; 2] = random_iv::<u32, 2>();
/// ```
pub fn random_iv<W, const N: usize>() -> [W; N]
where
    W: Word,
{
    let mut rng = thread_rng();
    from_fn(|_| W::random(&mut rng))
}

pub fn random_nonce_and_counter<W, const N: usize>() -> [W; N]
where
    W: Word,
{
    let mut rng = thread_rng();
    from_fn(|i| match i {
        n if n == N - 1 => W::ZERO,
        _ => W::random(&mut rng),
    })
}

pub fn pkcs7(buf: &mut Vec<u8>, bs: usize, pad: bool) -> Result<usize, Reason> {
    if pad {
        let rem = buf.len() % bs;
        let pad_count = if rem > 0 { bs - rem } else { bs };
        buf.extend(std::iter::repeat(pad_count as u8).take(pad_count));
        return Ok(rem);
    }

    let len = buf.len();
    let pad_len = *buf.last().unwrap() as usize;

    bail!(
        len == 0 || len % bs != 0,
        Reason::Padding,
        pad_len == 0 || pad_len > bs,
        Reason::Padding,
        !buf[len - pad_len..]
            .iter()
            .all(|element| *element == pad_len as u8),
        Reason::Padding
    );

    let padding = len - pad_len;
    buf.truncate(padding);
    Ok(pad_len)
}

#[cfg(test)]
mod tests {
    use super::pkcs7;
    use crate::Word;

    #[test]
    fn padding_fixed_blocks() {
        const BS: usize = 2 * u32::BYTES;

        let mut pt = vec![1_u8; 8];

        pkcs7(&mut pt, BS, true).unwrap();
        assert_eq!(pt, vec![1; 8]);

        let mut pt = vec![1_u8; 4];
        pkcs7(&mut pt, BS, true).unwrap();
        assert_eq!(pt, vec![1, 1, 1, 1, 4, 4, 4, 4]);
    }
}

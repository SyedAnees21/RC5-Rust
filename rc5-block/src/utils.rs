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
/// ```rust
/// // generates a pseudo-random iv of block size [u32;2]
/// let iv: [u32; 2] = rc5_block::random_iv::<u32, 2>();
/// ```
pub fn random_iv<W, const N: usize>() -> [W; N]
where
    W: Word,
{
    let mut rng = thread_rng();
    from_fn(|_| W::random(&mut rng))
}

/// Generate a pseudo‑random block of `N` words where the last word is zero
/// (suitable for use as a CTR‐mode nonce + counter seed).
///
/// - The first `N-1` words are random (`W::random`), which is a `nonce`.
/// - The last word is initialized to `W::ZERO`, which is a `counter` so
///   you can increment it per block.
///
/// # Panics
///
/// Panics if `N == 0`, since there is no “last” index to zero out.
///
/// # Examples
///
/// ```rust
/// let nc: [u32; 2] = rc5_block::random_nonce_and_counter::<u32, 2>();
/// assert_eq!(nc[1], 0); // counter initialized to zero
/// ```
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

/// Apply or remove PKCS#7 padding on the given buffer in place.
///
/// - If `pad == true`: appends padding bytes.
/// - If `pad == false`: remove the padded bytes.
///
/// It appends the padding bytes multiple of block size, if the
/// buffer is already the multiple of block size, it appends full
/// block size bytes.
///
/// # Examples
///
/// ```rust
/// let mut data = b"HELLO".to_vec();      // length 5
/// let rem = rc5_block::pkcs7(&mut data, 8, true).unwrap();
/// assert_eq!(rem, 5 % 8);                // 5
/// assert_eq!(data.len(), 8);             // padded to 8
/// assert_eq!(&data[5..], &[3,3,3]);       // 3 bytes of 0x03
///
/// // Unpadding example:
/// let mut data = data.clone();
/// let pad_len = rc5_block::pkcs7(&mut data, 8, false).unwrap();
/// assert_eq!(pad_len, 3);
/// assert_eq!(data, b"HELLO");
/// ```
///
/// Reutrns the number of bytes padded or removed.
pub fn pkcs7(buf: &mut Vec<u8>, bs: usize, pad: bool) -> Result<usize, Reason> {
    if pad {
        let rem = buf.len() % bs;
        let pad_count = if rem > 0 { bs - rem } else { bs };
        buf.extend(std::iter::repeat_n(pad_count as u8, pad_count));
        return Ok(rem);
    }

    let len = buf.len();

    // return the same error everytime just to avoid
    // oracle attacks on pading scheme.
    bail!(len == 0 || len % bs != 0, Reason::Padding);

    let pad_len = *buf.last().unwrap() as usize;

    bail!(
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
    use crate::Reason;

    #[test]
    fn pad_aligned_data() {
        let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let block_size = 8;

        let rem = pkcs7(&mut data, block_size, true).unwrap();
        assert_eq!(rem, 0); // already aligned
        assert_eq!(data.len(), 16);
        assert_eq!(&data[8..], &[8; 8]); // full block padding
    }

    #[test]
    fn pad_unaligned_data() {
        let mut data = b"hello".to_vec(); // 5 bytes
        let block_size = 8;

        let rem = pkcs7(&mut data, block_size, true).unwrap();
        assert_eq!(rem, 5);
        assert_eq!(data.len(), 8);
        assert_eq!(&data[5..], &[3, 3, 3]);
    }

    #[test]
    fn unpad_valid_data() {
        let mut data = b"world\x03\x03\x03".to_vec();
        let block_size = 8;

        let pad_len = pkcs7(&mut data, block_size, false).unwrap();
        assert_eq!(pad_len, 3);
        assert_eq!(data, b"world");
    }

    #[test]
    fn unpad_full_block_padding() {
        let mut data = b"messages\x08\x08\x08\x08\x08\x08\x08\x08".to_vec();
        let block_size = 8;

        let pad_len = pkcs7(&mut data, block_size, false).unwrap();
        assert_eq!(pad_len, 8);
        assert_eq!(data, b"messages");
    }

    #[test]
    fn unpad_invalid_trailing_bytes() {
        let mut data = b"bad\x04\x04\x04\x02".to_vec(); // last pad byte is wrong
        let block_size = 4;

        let result = pkcs7(&mut data, block_size, false);
        assert!(matches!(result, Err(Reason::Padding)));
    }

    #[test]
    fn unpad_invalid_padding_length_too_large() {
        let mut data = b"invalid\x09\x09\x09\x09\x09\x09\x09\x09\x09".to_vec(); // pad_len > block_size
        let block_size = 8;

        let result = pkcs7(&mut data, block_size, false);
        assert!(matches!(result, Err(Reason::Padding)));
    }

    #[test]
    fn unpad_invalid_buffer_not_multiple_of_block_size() {
        let mut data = b"oops\x04\x04\x04".to_vec(); // total len = 7, not a multiple of 8
        let block_size = 8;

        let result = pkcs7(&mut data, block_size, false);
        assert!(matches!(result, Err(Reason::Padding)));
    }

    #[test]
    fn unpad_empty_buffer() {
        let mut data = vec![];
        let block_size = 8;

        let result = pkcs7(&mut data, block_size, false);
        assert!(matches!(result, Err(Reason::Padding)));
    }
}

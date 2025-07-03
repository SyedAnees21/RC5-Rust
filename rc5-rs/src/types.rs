use rand::Rng;

/// # RC5 version identifier
///
/// It represents RC5 control block parameters. These parameters are
/// defined as follows:
///
/// 1. Algorithm version (1 for RC5)
/// 2. Word-size in bits
/// 3. Number of rounds.
/// 4. Key length in bytes.
///
/// This is how these parameters are arranged in version string:
///
/// RC5-v<`Algorithm version`>/<`Word-size`>/<`Rounds`>/<`Key-length`>
///
/// This can be useful when asserting what parametric version of RC5 to
/// use for certain applications.
pub struct Version(Vec<u8>);

impl Version {
    /// Construct a new `Version` from a 4‑element parameter vector.
    ///
    /// Expects the vector to be exactly four bytes:
    /// `[algorithm, word_bits, rounds, key_bytes]`.
    pub fn from_parametric_vector(params: Vec<u8>) -> Self {
        Self(params)
    }

    /// Render the RC5 version string in the form: `RC5-vA/B/C/D`.
    ///
    /// Where A,B,C,D correspond to the four parameters passed to `new`.
    pub fn version(&self) -> String {
        let params = &self.0;
        format!(
            "RC5-v{}/{}/{}/{}",
            params[0], params[1], params[2], params[3]
        )
    }
}

/// A core trait to define a word in `N-sized` blocks of a block cipher. This
/// word must support arithmatic and binary operations required for cryptographic
/// functions.
pub trait Word: Clone + Copy + std::ops::BitXor<Output = Self> {
    /// A constant zero value for a `Word` type.
    const ZERO: Self;

    /// Number of bytes in this word
    const BYTES: usize;

    /// Magic constant `P` represented by this word to
    /// be used in RC5 key expansion.
    const P: Self;

    /// Magic constant `Q` represented by this word to
    /// be used in RC5 key expansion.
    const Q: Self;

    /// Cast a 8-bit value to this word type.
    fn from_u8(val: u8) -> Self;

    /// Parse this word from a little‐endian byte slice of length `BYTES`.
    ///
    /// Returns `None` if the slice length is not equal to `Word::BYTES`
    fn from_bytes_slice(slice: &[u8]) -> Option<Self>;

    /// Serialize this word to a little‐endian bytes list.
    fn to_bytes_slice(&self) -> Vec<u8>;

    /// Generate a random word using the given RNG.
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self;

    /// Wrapped addition
    fn wrapping_add(self, val: Self) -> Self;

    /// Wrapped subtraction
    fn wrapping_sub(self, val: Self) -> Self;

    /// Left bitwise rotation
    fn rotate_left(self, bits: Self) -> Self;

    /// Right bitwise rotation
    fn rotate_right(self, bits: Self) -> Self;
}

macro_rules! magic_consts {
    (u16) => {
        const P: u16 = 0xb7e1;
        const Q: u16 = 0x9e37;
    };
    (u32) => {
        const P: u32 = 0xb7e15163;
        const Q: u32 = 0x9e3779b9;
    };
    (u64) => {
        const P: u64 = 0xb7e151628aed2a6b;
        const Q: u64 = 0x9e3779b97f4a7c15;
    };
    (u128) => {
        const P: u128 = 0x9E3779B97F4A7C15F39CC0605CEDC835;
        const Q: u128 = 0xB7E151628AED2A6ABF7158809CF4F3C7;
    }
}

macro_rules! impl_word_for_prim {
    ($($t:ident),*) => {
        $(
            impl Word for $t {
                const ZERO: $t = 0;
                const BYTES: usize = (<$t>::BITS / 8) as usize;

                magic_consts!($t);

                #[inline]
                fn from_u8(val: u8) -> Self {
                    val as $t
                }

                #[inline]
                fn from_bytes_slice(slice: &[u8]) -> Option<Self> {
                    slice.try_into().ok().map(|b| <$t>::from_le_bytes(b))
                }

                fn to_bytes_slice(& self) -> Vec<u8> {
                    self.to_le_bytes().to_vec()
                }

                #[inline]
               fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
                    rng.r#gen()
               }

                #[inline]
                fn wrapping_add(self, other: Self) -> Self {
                    <$t>::wrapping_add(self, other)
                }

                #[inline]
                fn wrapping_sub(self, other: Self) -> Self {
                    <$t>::wrapping_sub(self, other)
                }

                #[inline]
                fn rotate_left(self, bits: Self) -> Self {
                    self.rotate_left(bits as u32)
                }

                #[inline]
                fn rotate_right(self, bits: Self) -> Self {
                    self.rotate_right(bits as u32)
                }
            }
        )*
    }
}

impl_word_for_prim!(u16, u32, u64, u128);

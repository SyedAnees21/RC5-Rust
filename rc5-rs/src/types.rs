use rand::Rng;

pub struct Version(Vec<u8>);

impl Version {
    pub fn from_parametric_vector(params: Vec<u8>) -> Self {
        Self(params)
    }

    pub fn version(&self) -> String {
        let params = &self.0;
        format!(
            "RC5-v{}/{}/{}/{}",
            params[0], params[1], params[2], params[3]
        )
    }
}

pub trait Word: Clone + Copy + std::ops::BitXor<Output = Self> {
    const ZERO: Self;
    const BYTES: usize;
    const P: Self;
    const Q: Self;

    fn from_u8(val: u8) -> Self;

    fn from_bytes_slice(slice: &[u8]) -> Option<Self>;
    fn to_bytes_slice(&self) -> Vec<u8>;

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self;

    fn wrapping_add(self, val: Self) -> Self;
    fn wrapping_sub(self, val: Self) -> Self;
    fn rotate_left(self, bits: Self) -> Self;
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

impl_word_for_prim!(u16, u32, u64);

use crate::{BlockCipher, Version, Word};

pub struct RC5ControlBlock<W: Word> {
    version: Version,
    key: RC5Key<W>,
    rounds: usize,
}

impl<W: Word> RC5ControlBlock<W> {
    pub fn new<K>(key: K, rounds: usize) -> Self 
    where 
        K: AsRef<[u8]>
    {
        let key = RC5Key::from_raw(key, rounds);

        Self {
            rounds,
            version: Version::from_parametric_vector(vec![
                1,
                (W::BYTES * 8) as u8,
                rounds as u8,
                key.raw_len() as u8,
            ]),
            key,
        }
    }

    #[inline]
    pub fn s_table(&self) -> &[W] {
        &self.key.s_table
    }

    #[inline]
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    #[inline]
    pub fn parametric_version(&self) -> String {
        self.version.version()
    }
}

impl<W: Word> BlockCipher<W, 2> for RC5ControlBlock<W> {
    fn encrypt(&self, pt: [W; 2]) -> [W; 2] {
        let expanded_key = self.s_table();
        let [mut word_a, mut word_b] = pt;

        word_a = word_a.wrapping_add(expanded_key[0]);
        word_b = word_b.wrapping_add(expanded_key[1]);

        for r in 1..=self.rounds() {
            word_a = ((word_a ^ word_b).rotate_left(word_b)).wrapping_add(expanded_key[2 * r]);
            word_b = ((word_b ^ word_a).rotate_left(word_a)).wrapping_add(expanded_key[2 * r + 1]);
        }

        [word_a, word_b]
    }

    fn decrypt(&self, ct: [W; 2]) -> [W; 2] {
        let expanded_key = self.s_table();
        let [mut word_a, mut word_b] = ct;

        for r in (1..=self.rounds()).rev() {
            word_b = (word_b
                .wrapping_sub(expanded_key[2 * r + 1])
                .rotate_right(word_a))
                ^ word_a;

            word_a = (word_a
                .wrapping_sub(expanded_key[2 * r])
                .rotate_right(word_b))
                ^ word_b;
        }

        word_b = word_b.wrapping_sub(expanded_key[1]);
        word_a = word_a.wrapping_sub(expanded_key[0]);

        [word_a, word_b]
    }

    fn generate_blocks(&self, pt: Vec<u8>) -> Vec<[W; 2]> {
        let mut blocks = Vec::with_capacity(pt.len() / self.block_size());
        for chunks in pt.chunks_exact(self.block_size()) {
            blocks.push([
                W::from_bytes_slice(&chunks[..W::BYTES]).unwrap(),
                W::from_bytes_slice(&chunks[W::BYTES..]).unwrap(),
            ]);
        }

        blocks
    }

    fn generate_bytes_stream(&self, blocks: Vec<[W; 2]>) -> Vec<u8> {
        let mut stream = Vec::with_capacity(blocks.len() * self.block_size());
        for blcok in blocks.iter() {
            stream.extend_from_slice(&blcok[0].to_bytes_slice());
            stream.extend_from_slice(&blcok[1].to_bytes_slice());
        }
        stream
    }

    fn block_size(&self) -> usize {
        W::BYTES * 2
    }
}

const MAX_KEY_BYTES: usize = 255;

pub struct RC5Key<W: Word> {
    raw_key: Vec<u8>,
    s_table: Vec<W>,
}

impl<W: Word> RC5Key<W> {
    pub fn from_raw<K>(raw: K, rounds: usize) -> Self 
    where 
        K: AsRef<[u8]>
    {
        let key_bytes = raw.as_ref();

        assert!(
            key_bytes.len() <= MAX_KEY_BYTES,
            "[RC5-Error] Restricted key length {}, Max key length supported {}",
            key_bytes.len(),
            MAX_KEY_BYTES
        );

        Self {
            s_table: expand_key::<W>(key_bytes, rounds),
            raw_key: key_bytes.to_vec(),
        }
    }

    pub fn raw_len(&self) -> usize {
        self.raw_key.len()
    }
}

fn expand_key<W: Word>(key: &[u8], rounds: usize) -> Vec<W> {
    let word_bytes = W::BYTES;
    let key_length = key.len().max(1);

    let expanded_length = (key_length + word_bytes - 1) / word_bytes;
    let mut key_words = vec![W::ZERO; expanded_length];

    for index in (0..key_length).rev() {
        let ix = index / word_bytes;
        key_words[ix] = key_words[ix]
            .rotate_left(W::from_u8(8))
            .wrapping_add(W::from_u8(key[index]));
    }

    let table_size = 2 * (rounds + 1);
    let mut s_table = vec![W::ZERO; table_size];

    s_table[0] = W::P;

    for i in 1..table_size {
        s_table[i] = s_table[i - 1].wrapping_add(W::Q);
    }

    let (mut i, mut j) = (0, 0);
    let (mut a, mut b) = (W::ZERO, W::ZERO);

    for _ in 0..(3 * table_size.max(expanded_length)) {
        a = s_table[i]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(W::from_u8(3));

        b = key_words[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(a.wrapping_add(b));

        s_table[i] = a;
        key_words[j] = b;

        i = (i + 1) % table_size;
        j = (j + 1) % expanded_length;
    }

    s_table
}

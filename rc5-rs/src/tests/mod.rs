use crate::{BlockCipher, RC5ControlBlock, Reason};

mod cbc;
mod ctr;
mod ecb;

macro_rules! rc5_control_block_vectors {
    ($( $fn_name:ident: ( $key:expr , $rounds:expr , $exp_cipher:expr , $exp_dec:expr) ),*$(,)?) => {
        $(
            #[test]
            fn $fn_name() -> Result<(), Reason> {
                let key = ($key as u128).to_be_bytes();
                let plain_text = [0_u32;2];
                let rc5_block = RC5ControlBlock::<u32>::new(key, $rounds)?;

                let cipher_text = rc5_block.encrypt(plain_text);

                let bytes = cipher_text
                            .iter()
                            .flat_map(|word| word.to_le_bytes())
                            .collect::<Vec<u8>>();

                assert_eq!($exp_cipher, hex::encode_upper(bytes));

                let decipher_text = rc5_block.decrypt(cipher_text);

                assert_eq!($exp_dec, decipher_text);

                Ok(())
            }
        )*
    };
}

// Standard test-vetors
// see more: https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Rc5-128-64.verified.test-vectors
rc5_control_block_vectors! {
    rc5_control_block_vector_1: (
        0x80000000000000000000000000000000,
        12,
        String::from("8F681D7F285CDC2F"),
        [0_u32;2]
    ),
    rc5_control_block_vector_2: (
        0x40000000000000000000000000000000,
        12,
        String::from("DC14832CF4FE61A8"),
        [0_u32;2]
    ),
    rc5_control_block_vector_3: (
        0x20000000000000000000000000000000,
        12,
        String::from("2F2494A0D96958E7"),
        [0_u32;2]
    ),
    rc5_control_block_vector_4: (
        0x10000000000000000000000000000000,
        12,
        String::from("410BCDD35DA0963F"),
        [0_u32;2]
    ),
    rc5_control_block_vector_5: (
        0x08000000000000000000000000000000,
        12,
        String::from("0C4C1EC0EA4EA260"),
        [0_u32;2]
    ),
    rc5_control_block_vector_6: (
        0x04000000000000000000000000000000,
        12,
        String::from("3BBC9C778EDC72B3"),
        [0_u32;2]
    ),
    rc5_control_block_vector_7: (
        0x02000000000000000000000000000000,
        12,
        String::from("06381C693372158D"),
        [0_u32;2]
    ),
    rc5_control_block_vector_8: (
        0x01000000000000000000000000000000,
        12,
        String::from("587E3D5E4B11860B"),
        [0_u32;2]
    ),
}

use crate::{BlockCipher, OperationMode, Reason, rc5_cipher};

macro_rules! rc5_cbc_round_trip {
    ($( $fn_name:ident: ( $w:ty , $key:expr , $rounds:expr , $pt:expr) ),*$(,)?) => {
        $(
            #[test]
            fn $fn_name() -> Result<(), Reason> {
                let cipher = rc5_cipher::<$w>(&$key, $rounds)?;
                let plain_text = $pt.as_bytes().to_vec();
                let random_nonce = crate::random_nonce_and_counter();

                let ct_bytes = cipher.encrypt(&plain_text, OperationMode::CTR {nonce_and_counter: random_nonce })?;
                let dt_bytes = cipher.decrypt(&ct_bytes, OperationMode::CTR {nonce_and_counter: random_nonce })?;

                assert_eq!(
                    plain_text,
                    dt_bytes,
                    "{}",
                    format!("Round trip failed for {}", cipher.control_block().control_block_version())
                );

                Ok(())
            }
        )*
    };
}

rc5_cbc_round_trip! {
    rc5_ctr_16_8_8:  (
        u16,
        [0u8; 8],
        8,
        "This is RC5-CTR 16-bit word size test."
    ),
    rc5_ctr_16_8_12:  (
        u16,
        [0u8; 8],
        12,
        "This is RC5-CTR 16-bit word size test."
    ),
    rc5_ctr_32_16_12:  (
        u32,
        [0u8; 16],
        12,
        "This is RC5-CTR 32-bit word size test."
    ),
    rc5_ctr_64_24_20:  (
        u64,
        [0u8; 24],
        20,
        "This is RC5-CTR 64-bit word size test."
    ),
}

use crate::{BlockCipher, RC5ControlBlock, Reason, rc5_cipher, utils::random_nonce_and_counter};

mod ecb;
mod cbc;
mod ctr;

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

#[test]
fn encrypt_word_32() -> Result<(), Reason> {
    let key = vec![2_u8; 16];
    let pt = [0_u32; 2];
    let rounds = 12;

    let rc5 = RC5ControlBlock::<u32>::new(key, rounds)?;
    let cipher = rc5.encrypt(pt);
    println!("Cipher: {:?}", cipher);

    let text = rc5.decrypt(cipher);

    println!("{:#010x?}", pt);
    println!("{:#010x?}", text);

    println!("{}", rc5.parametric_version());

    Ok(())
}

#[test]
fn rc5_cipher_contructor() -> Result<(), Reason> {
    use crate::{Word, rc5_cipher};

    let key = vec![2_u8; 16];
    let rounds = 12;

    let cipher = rc5_cipher::<u32>(&key, rounds)?;

    let pt = b"Anees UR";

    let ct = cipher.encrypt(pt, crate::OperationMode::ECB)?;

    dbg!(ct.len(), ct.clone());

    let de_pt = cipher.decrypt(ct.as_ref(), crate::OperationMode::ECB)?;

    dbg!(str::from_utf8(&de_pt));

    Ok(())
}

#[test]
fn rc5_cbc_test() -> Result<(), Reason> {
    let key = [0_u8; 16];
    let rounds = 12;
    let cipher = crate::rc5_cipher::<u32>(key.to_vec(), rounds)?;
    let random_iv = crate::random_iv();

    let pt = b"Syed Anees Ur Rehman";
    let ct = cipher.encrypt(pt, crate::OperationMode::ECB)?;
    dbg!(&ct);

    let d = cipher.decrypt(&ct, crate::OperationMode::ECB);
    dbg!(d);

    let ct = cipher.encrypt(
        b"This is my cipher!!",
        crate::OperationMode::CBC { iv: random_iv },
    )?;
    dbg!(String::from_utf8_lossy(&ct));
    dbg!(String::from_utf8_lossy(
        &cipher.decrypt(&ct, crate::OperationMode::CBC { iv: random_iv })?
    ));

    Ok(())
}

#[test]
fn rc5_ctr() -> Result<(), Reason> {
    let key: [u8; 16] = (*b"SECRET_KEY_BYTES").into();
    let rounds = 12;
    let random_nonce = random_nonce_and_counter();
    let plain = b"This is RC5-CTR test";

    let rc5_cipher = rc5_cipher::<u32>(key.to_vec(), rounds)?;

    let ct = rc5_cipher.encrypt(
        plain,
        crate::OperationMode::CTR {
            nonce_and_counter: random_nonce,
        },
    )?;

    dbg!(String::from_utf8_lossy(&ct));

    let d_plain = rc5_cipher.decrypt(
        &ct,
        crate::OperationMode::CTR {
            nonce_and_counter: random_nonce,
        },
    )?;
    dbg!(String::from_utf8(d_plain));

    Ok(())
}

#[test]
fn rc5_ecb_32_bit() -> Result<(), Reason> {
    let key: [u8; 16] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let rounds = 99;
    let plain_text = [0u32; 2];

    let rc5_cipher = RC5ControlBlock::<u32>::new(key, rounds)?;

    let cipher_text = rc5_cipher.encrypt(plain_text);
    let bytes = cipher_text
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<u8>>();
    println!("{:?}", hex::encode_upper(bytes));
    // hex::decode("abc")?;
    // println!("{:0x?}", u64::from_bytes_slice(&bytes));

    let a = 0x80000000000000000000000000000000u128;

    println!("{:?}", a.to_be_bytes());

    let decipher_text = rc5_cipher.decrypt(cipher_text);

    println!("{:0x?}", decipher_text);

    Ok(())
}

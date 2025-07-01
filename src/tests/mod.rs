use crate::{rc5_cipher, utils::random_nonce_and_counter, BlockCipher, OperationMode, RC5ControlBlock, Word};

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

    let cipher = rc5_cipher::<u32>(&key, rounds);

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
    let cipher = crate::rc5_cipher::<u32>(key.to_vec(), rounds);
    let random_iv = crate::random_iv();

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

#[test]
fn rc5_ctr() {
    let key: [u8; 16] = (*b"SECRET_KEY_BYTES").into();
    let rounds = 12;
    let random_nonce = random_nonce_and_counter();
    let plain = b"This is RC5-CTR test";

    let rc5_cipher = rc5_cipher::<u32>(key.to_vec(), rounds);

    let ct = rc5_cipher
        .encrypt(
            plain,
            crate::OperationMode::CTR {
                nonce_and_counter: random_nonce,
            },
        )
        .unwrap();

    dbg!(String::from_utf8_lossy(&ct));

    let d_plain = rc5_cipher
        .decrypt(
            &ct,
            crate::OperationMode::CTR {
                nonce_and_counter: random_nonce,
            },
        )
        .unwrap();
    dbg!(String::from_utf8(d_plain));
}

#[test]
fn rc5_ecb_32_bit() {
    let key: [u8; 16] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    let rounds = 100;
    let plain_text = [0u32;2];

    let rc5_cipher = RC5ControlBlock::<u32>::new(key, rounds);

    let cipher_text = rc5_cipher.encrypt(plain_text);
    let bytes = cipher_text.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<u8>>();
    println!("{:0x?}", u64::from_bytes_slice(&bytes));

    let decipher_text = rc5_cipher.decrypt(cipher_text);
    println!("{:0x?}", decipher_text);

}
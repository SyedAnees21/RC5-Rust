use crate::{RC5ControlBlock, BlockCipher, Word};

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
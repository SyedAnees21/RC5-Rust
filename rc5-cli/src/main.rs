use clap::Parser;
use opts::{Mode, Opts};
use rc5_rs::{BlockCipher, random_iv, random_nonce_and_counter, rc5_cipher};

mod opts;

macro_rules! get_cipher {
    ($opts:expr) => {{
        let cipher;

        #[cfg(feature = "word-16")]
        {
            cipher = rc5_cipher::<u16>($opts.secret.as_str(), $opts.rounds)?;
        }

        #[cfg(feature = "word-32")]
        {
            cipher = rc5_cipher::<u32>($opts.secret.as_str(), $opts.rounds)?;
        }

        #[cfg(feature = "word-64")]
        {
            cipher = rc5_cipher::<u64>($opts.secret.as_str(), $opts.rounds)?;
        }

        cipher
    }};
}

fn main() -> anyhow::Result<()> {
    let options = Opts::parse();
    let cipher = get_cipher!(options);

    match options.mode {
        Mode::ECB => todo!(),
        Mode::CBC { iv } => {
            let iv = match iv {
                Some(iv_hex) => cipher.parse_iv_from_hex(iv_hex)?,
                None => random_iv(),
            };
        }
        Mode::CTR { nonce, counter } => {
            let nonce_and_counter = match (nonce, counter) {
                (Some(nonce_hex), Some(counter_hex)) => {
                    cipher.parse_nonce_counter_from_hex(nonce_hex, counter_hex)?
                }
                (_, _) => random_nonce_and_counter(),
            };
        }
    }
    println!("{:#?}", cipher.control_block().parametric_version());
    // println!("Hello, world!");
    Ok(())
}

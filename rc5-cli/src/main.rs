use clap::Parser;
use opts::{Mode, Opts};
use rc5_rs::{OperationMode, random_iv, random_nonce_and_counter, rc5_cipher};
use std::io::Write;

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
        #[cfg(feature = "word-128")]
        {
            cipher = rc5_cipher::<u128>($opts.secret.as_str(), $opts.rounds)?;
        }

        cipher
    }};
}

fn main() -> anyhow::Result<()> {
    let options = Opts::parse();
    let text = std::fs::read(&options.file)?;

    let cipher = get_cipher!(options);

    let mut processed = match options.mode {
        Mode::ECB => match options.action {
            opts::Action::Encrypt => cipher.encrypt(&text, OperationMode::ECB)?,
            opts::Action::Decrypt => cipher.decrypt(&text, OperationMode::ECB)?,
        },
        Mode::CBC { ref iv } => {
            let iv = match iv {
                Some(iv_hex) => cipher.parse_iv_from_hex(iv_hex)?,
                None => random_iv(),
            };

            match options.action {
                opts::Action::Encrypt => cipher.encrypt(&text, OperationMode::CBC { iv })?,
                opts::Action::Decrypt => cipher.decrypt(&text, OperationMode::CBC { iv })?,
            }
        }
        Mode::CTR {
            ref nonce,
            ref counter,
        } => {
            let nonce_and_counter = match (nonce, counter) {
                (Some(nonce_hex), Some(counter_hex)) => {
                    cipher.parse_nonce_counter_from_hex(nonce_hex, counter_hex)?
                }
                (_, _) => random_nonce_and_counter(),
            };

            match options.action {
                opts::Action::Encrypt => {
                    cipher.encrypt(&text, OperationMode::CTR { nonce_and_counter })?
                }
                opts::Action::Decrypt => {
                    cipher.decrypt(&text, OperationMode::CTR { nonce_and_counter })?
                }
            }
        }
    };

    let dest = options.dest_path();
    let mut f = std::fs::File::create(dest)?;
    f.write_all(&mut processed)?;
    f.flush()?;

    Ok(())
}

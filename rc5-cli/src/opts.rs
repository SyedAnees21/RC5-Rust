use clap::{Parser, Subcommand};

const ABOUT: &str = "A command-line RC5 encryption/decryption tool";
const LONG_ABOUT: &str = "\
rc5-cli is a flexible and extensible tool that provides RC5 encryption and decryption \
using multiple block modes like ECB, CBC, and CTR. It supports variable word sizes and \
key lengths for advanced cryptographic workflows. Use this tool to encrypt or decrypt data securely.";

#[derive(Parser, Debug)]
#[command(name = "rc5-cli" ,version, about = ABOUT, long_about = LONG_ABOUT)]
pub struct Opts {
    /// Secret-key to be used by RC5 control block
    /// for encryption.
    #[clap(short, long)]
    secret: String,

    /// Number of encryption/decryption iterations
    /// to perform.
    #[clap(short, long)]
    rounds: usize,

    /// Which operation-mode to use for encryption/
    /// decryption.
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
pub enum Mode {
    /// Electronic-Code-Book operation mode
    ECB,

    /// Cipher-Block-Chaining operation mode
    CBC {
        /// Initialization-Vector, to be provided
        /// as a hex string.
        #[clap(long)]
        iv: Option<String>,
    },

    /// Counter operation mode
    CTR {
        /// A unique nonce for counter encrytion.
        #[clap(short, long)]
        nonce: Option<String>,
        /// An arbitrary initial counter value.
        #[clap(short, long)]
        counter: Option<u64>,
    },
}

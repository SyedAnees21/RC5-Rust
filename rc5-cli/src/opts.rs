use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    pub secret: String,

    /// Number of encryption/decryption iterations
    /// to perform.
    #[clap(short, long)]
    pub rounds: usize,

    /// Source file path to load the encrypted/
    /// decrypted file.
    #[clap(short, long)]
    pub file: PathBuf,

    /// Destination file path to store the encrypted/
    /// decrypted file.
    #[clap(short, long)]
    pub dest: Option<PathBuf>,

    /// Which operation-mode to use for encryption/
    /// decryption.
    #[command(subcommand)]
    pub mode: Mode,

    /// What action to perform either to encrypt or
    /// to decrypt
    #[clap(short, long)]
    pub action: Action,
}

impl Opts {
    pub fn dest_path(&self) -> PathBuf {
        if let Some(path) = &self.dest {
            return path.clone();
        }

        let mut path = PathBuf::new();
        path.push("./");
        path.push("processed.txt");

        path
    }
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
        counter: Option<String>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Action {
    Encrypt,
    Decrypt,
}

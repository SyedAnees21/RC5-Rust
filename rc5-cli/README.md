# RC5-CLI

A command‑line utility for encrypting and decrypting files or data streams using the RC5 block cipher. This tool is built
in rust using the [rc5-rs](./README.md) a rust lib. This tool can be compiled for different word sizes can compile time and
can operate in different operation modes.

## Build

This tool can be built for different word sizes using cargo features at compile time using this command:

```Shell
# Default 32-bit compilation, tool will be compiled for 32 bit word size
cargo build --release

# 128 bit word size compilation
cargo build --release --no-default-features --features word-128
```

For command line help you can run the following commands:

```Shell
# using directly exe
./target/release/rc5-cli.exe -h

# Using cargo command
cargo run --release -- -h
```

## Quick-Start

Once the tool is built, you can run this tool to encrypt any file or byte stream at runtime, for example:

```Shell
# Encrypting toml file located at the root using a secret key with 12 iterations for encryption in ECB mode.
# Encrypted file will be generated at the root of the directoy with default name "processed.txt"
cargo run --release -- --secret "VERY_SECRET_KEY" --rounds 12 --file ./Cargo.toml --action encrypt ecb

# Now decrypting the generated file again to get back the toml file, this time we are providing a destination
# path along with the file name in which we want to decrypt
cargo run --release -- --secret "VERY_SECRET_KEY" --rounds 12 --file ./processed.txt --dest ./Cargo-2.toml --action decrypt ecb

# Above command may also be written using the short-hand key words like this
cargo run --release -- -s "VERY_SECRET_KEY" -r 12 -f ./processed.txt -d ./Cargo-2.toml -a decrypt ecb
```

To encrypt a file using different operation mode can be done like this:

```Shell
# Encrypting the toml file using CBC operation mode with a securely generated IV and storing the
# encrypted file as ciphered.txt at root. Make sure that the iv is equal to the block size, e.g 
# in our case we are using 32 bit word so our block size is 64 ibt.
cargo run --release -- -s "VERY_SECRET_KEY" -r 12 -f ./Cargo.toml -d ./ciphered.txt -a encrypt cbc --iv DEADBEEFCAFEBABE

# Decrypting the generated ciphered text back to toml 
cargo run --release -- -s "VERY_SECRET_KEY" -r 12 -f ./ciphered.tt -d ./Cargo-2.toml -a decrypt cbc --iv DEADBEEFCAFEBABE
```
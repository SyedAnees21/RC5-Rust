use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Opts {
    /// Secret-key to be used by RC5 control block
    /// for encryption.
    #[arg(short, long)]
    secret: String,
}

fn main() {
    let options = Opts::parse();
    // println!("Hello, world!");
}

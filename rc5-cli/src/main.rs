use clap::Parser;
use opts::{Mode, Opts};

mod opts;

fn main() {
    let options = Opts::parse();
    println!("{:#?}", options);
    // println!("Hello, world!");
}

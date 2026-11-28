//! Exercise only the public crate on raw inputs from the existing quantity corpus.
use rust_decimal::Decimal;
use std::error::Error;
use std::io::{self, BufRead};

fn main() -> Result<(), Box<dyn Error>> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (raw, _) = line.split_once('\t').ok_or("missing preparation columns")?;
        let raw: u64 = raw.parse()?;
        let value = Decimal::from_i128_with_scale(i128::from(raw), 8).normalize();
        println!("{raw}\t{value}");
    }
    Ok(())
}

//! Input-only fixed-record client, with no embedded expected answers.
use node94_keyword_classifiers::{classify, AccessError, Classifier};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 98 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(98) {
        if row[0] > 2 || row[33] > 64 {
            return Err("selector or image length exceeds backing storage".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(98) {
        let classifier = match row[0] {
            0 => Classifier::UntilRequiredMatches,
            1 => Classifier::VipMm,
            _ => Classifier::InputGasLimit,
        };
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let mut image: [u8; 64] = row[34..].try_into()?;
        let (tag, value) = match classify(
            &mut image[..usize::from(row[33])],
            word(1),
            word(9),
            word(17),
            word(25),
            classifier,
        ) {
            Ok(value) => (0, value),
            Err(AccessError::ImageRange) => (1, 0),
            Err(AccessError::Input) => (2, 0),
            Err(AccessError::Output) => (3, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}

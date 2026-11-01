use node94_chained_field_pair::{AccessError, Field, extract};
use std::io::{Read, Write};

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn main() {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).unwrap();
    if data.len() % 283 != 0 {
        eprintln!("partial chained-field input");
        std::process::exit(2);
    }
    if data
        .chunks_exact(283)
        .any(|r| r[0] > 1 || u16::from_le_bytes(r[25..27].try_into().unwrap()) > 256)
    {
        eprintln!("invalid chained-field descriptor");
        std::process::exit(2);
    }
    let mut output = Vec::with_capacity(data.len() / 283 * 265);
    for row in data.chunks_exact(283) {
        let field = if row[0] == 0 {
            Field::Signed32
        } else {
            Field::Word64
        };
        let length = usize::from(u16::from_le_bytes(row[25..27].try_into().unwrap()));
        let mut image: [u8; 256] = row[27..].try_into().unwrap();
        let result = extract(
            field,
            &mut image[..length],
            word(&row[1..9]),
            word(&row[9..17]),
            word(&row[17..25]),
        );
        let (tag, rax) = match result {
            Ok(rax) => (0, rax),
            Err(e) => (
                match e {
                    AccessError::ImageRange => 1,
                    AccessError::FirstPointer => 2,
                    AccessError::SecondPointer => 3,
                    AccessError::Value => 4,
                    AccessError::Output => 5,
                },
                0,
            ),
        };
        output.push(tag);
        output.extend_from_slice(&rax.to_le_bytes());
        output.extend_from_slice(&image);
    }
    std::io::stdout().write_all(&output).unwrap();
}

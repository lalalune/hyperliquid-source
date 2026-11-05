//! Owned offline test adapter: hex input, limit-or-dash, initial charge.
use node115_four_word_prefix::{Decoder, Error};
use node115_u64_reader_state::Error as ReadError;
use std::io::{self, BufRead, Write};

fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let cells: Vec<_> = line.split('\t').collect();
        assert_eq!(cells.len(), 3);
        assert_eq!(cells[0].len() % 2, 0);
        let input: Vec<u8> = (0..cells[0].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cells[0][i..i + 2], 16).unwrap())
            .collect();
        let limit = if cells[1] == "-" {
            None
        } else {
            Some(cells[1].parse().unwrap())
        };
        let mut decoder = Decoder::new(&input, limit, cells[2].parse().unwrap());
        match decoder.decode() {
            Ok(fields) => {
                let [a, b, c, d] = fields.words;
                write!(out, "[[\"ok\",[{a},{b},{c},{d}],").unwrap();
                if let Some(v) = fields.tail {
                    write!(out, "{v}").unwrap();
                } else {
                    write!(out, "null").unwrap();
                }
                write!(out, "]").unwrap();
            }
            Err(Error::Mode { found_raw }) => write!(out, "[[\"mode\",{found_raw}]").unwrap(),
            Err(Error::Read(ReadError::UnexpectedEnd { additional })) => {
                write!(out, "[[\"end\",{additional}]").unwrap()
            }
            Err(Error::Read(ReadError::Limit)) => write!(out, "[[\"limit\"]").unwrap(),
            Err(Error::Read(ReadError::Invalid {
                expected_raw,
                found_raw,
            })) => write!(out, "[[\"invalid\",{expected_raw},{found_raw}]").unwrap(),
        }
        writeln!(
            out,
            ",{},{}]",
            input.len() - decoder.remaining().len(),
            decoder.charged()
        )
        .unwrap();
    }
}

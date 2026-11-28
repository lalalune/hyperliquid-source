//! Compare the actual exported block API with the source-qualified public codec.
use std::error::Error;
use std::io::{self, Read, Write};

fn pop_record<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], io::Error> {
    let mut header = [0; 4];
    input.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    let (record, tail) = input
        .split_at_checked(len)
        .ok_or(io::ErrorKind::UnexpectedEof)?;
    *input = tail;
    Ok(record)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut corpus = Vec::new();
    io::stdin().lock().read_to_end(&mut corpus)?;
    let mut remaining = corpus.as_slice();
    let mut output = io::BufWriter::new(io::stdout().lock());
    while !remaining.is_empty() {
        let data = pop_record(&mut remaining)?;
        let local = net_utils::compress_prepend_size(data)?;
        let reference = lz4_flex::block::compress_prepend_size(data);
        if lz4_flex::block::decompress_size_prepended(&local)? != data
            || net_utils::decompress_size_prepended(&reference, data.len() as u64)? != data
        {
            return Err("decoded input differs".into());
        }
        for block in [&local, &reference] {
            output.write_all(&u32::try_from(block.len())?.to_le_bytes())?;
            output.write_all(block)?;
        }
    }
    output.flush()?;
    Ok(())
}

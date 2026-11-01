use node94_object_status_gates::{Member, evaluate};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 808 != 0 {
        return Err("partial object-status-gates input".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(808) {
        let mut fields = [0u64; 5];
        for (field, bytes) in fields.iter_mut().zip(row[..40].chunks_exact(8)) {
            *field = u64::from_le_bytes(bytes.try_into()?);
        }
        if fields[0] > 2 || fields[4] > 768 {
            return Err("invalid object-status-gates descriptor".into());
        }
        let member = match fields[0] {
            0 => Member::ThreeValued,
            1 => Member::PointerFlag,
            _ => Member::CounterGate,
        };
        let result = evaluate(
            member,
            &row[40..40 + fields[4] as usize],
            fields[1],
            fields[2],
            fields[3],
        );
        let words = match result {
            Some(r) => [1, r.rax, r.rdx],
            None => [0; 3],
        };
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
    }
    output.flush()?;
    Ok(())
}

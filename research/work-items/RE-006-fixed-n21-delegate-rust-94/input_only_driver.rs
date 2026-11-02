use std::io::{Read, Write};
use node94_orderbook::{n21_seed_prepare::sort_delegate21, n21_right_merge::PreparedPrefixError};

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at+8].try_into().unwrap())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input=Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    if input.len()<12 || &input[..8]!=b"S21IN001" { return Err("input frame".into()); }
    let count=u32::from_le_bytes(input[8..12].try_into()?) as usize;
    if count>10_000 || input.len()!=12+468*count { return Err("input length/count".into()); }
    let mut result=b"S21OUT02".to_vec();
    result.extend_from_slice(&(count as u32).to_le_bytes());
    for index in 0..count {
        let at=12+468*index;
        let id=u32::from_le_bytes(input[at..at+4].try_into()?);
        let mut output=std::array::from_fn(|j|word(&input,at+4+8*j));
        let mut scratch=std::array::from_fn(|j|word(&input,at+4+8*(21+j)));
        let projection=sort_delegate21(&mut output,&mut scratch);
        let status:u32=match &projection.continuation {
            Ok(_)=>0,
            Err(PreparedPrefixError::LeftUnsorted)=>1,
            Err(PreparedPrefixError::RightSeedUnsorted)=>2,
        };
        result.extend_from_slice(&id.to_le_bytes());
        result.extend_from_slice(&status.to_le_bytes());
        for value in projection.source_after_seeds.into_iter()
            .chain(projection.scratch_after_seeds)
            .chain(projection.prepared_scratch)
            .chain(output)
            .chain(scratch) {
            result.extend_from_slice(&value.to_le_bytes());
        }
    }
    std::io::stdout().write_all(&result)?;
    Ok(())
}

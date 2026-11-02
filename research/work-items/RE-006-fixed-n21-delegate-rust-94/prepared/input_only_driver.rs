use std::io::{Read, Write};
use node94_orderbook::n21_right_merge::{finish_prepared, Area, Half, PreparedPrefixError};

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn u32out(out: &mut Vec<u8>, value: usize) { out.extend_from_slice(&(value as u32).to_le_bytes()); }
fn u64out(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn side(half: Half) -> usize { match half { Half::Left => 0, Half::Right => 1 } }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = Vec::new();
    std::io::stdin().read_to_end(&mut raw)?;
    if raw.len() < 12 || &raw[..8] != b"N21IN001" { return Err("input frame".into()); }
    let count = u32::from_le_bytes(raw[8..12].try_into()?) as usize;
    if count > 10_000 || raw.len() != 12 + 468 * count { return Err("input length/count".into()); }
    let mut out = b"N21OUT01".to_vec();
    u32out(&mut out, count);
    for row in 0..count {
        let at = 12 + row * 468;
        let id = u32::from_le_bytes(raw[at..at + 4].try_into()?) as usize;
        let mut output = [0; 21];
        let mut scratch = [0; 37];
        for (index, value) in output.iter_mut().enumerate() { *value = word(&raw, at + 4 + index * 8); }
        for (index, value) in scratch.iter_mut().enumerate() { *value = word(&raw, at + 4 + (21 + index) * 8); }
        let window: &mut [u64; 21] = (&mut scratch[..21]).try_into()?;
        let result = finish_prepared(&mut output, window);
        u32out(&mut out, id);
        u32out(&mut out, match &result {
            Ok(_) => 0,
            Err(PreparedPrefixError::LeftUnsorted) => 1,
            Err(PreparedPrefixError::RightSeedUnsorted) => 2,
        });
        for value in output.into_iter().chain(scratch) { u64out(&mut out, value); }
        match result {
            Ok(observation) => {
                for index in observation.insertion_indices { u32out(&mut out, index); }
                u32out(&mut out, side(observation.center_from));
                for cursor in observation.final_cursors { u32out(&mut out, cursor); }
                for pair in observation.pairs {
                    for choice in [pair.front_retired, pair.back_value_loaded_from, pair.back_retired] {
                        u32out(&mut out, side(choice));
                    }
                }
                u32out(&mut out, observation.write_count);
                for event in observation.writes {
                    u32out(&mut out, match event.area { Area::Scratch => 0, Area::Output => 1 });
                    u32out(&mut out, event.index);
                    u64out(&mut out, event.value);
                }
            }
            Err(_) => out.extend_from_slice(&[0; 1020]),
        }
    }
    std::io::stdout().write_all(&out)?;
    Ok(())
}

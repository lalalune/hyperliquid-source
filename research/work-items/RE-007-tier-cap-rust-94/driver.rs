//! Input-only local comparison client. No target ABI or expected answers.
use std::io::{self, Read, Write};
use node94_margin_risk::{MarginTable, RawMarginTable, RawMarginTier, position_leverage_cap};

fn take<const N: usize>(raw: &[u8], at: &mut usize) -> Result<[u8; N], ()> {
    let end = at.checked_add(N).ok_or(())?;
    let out = raw.get(*at..end).ok_or(())?.try_into().map_err(|_| ())?;
    *at = end;
    Ok(out)
}
fn decode(raw: &[u8]) -> Result<Vec<u8>, ()> {
    let mut at = 0;
    if &take::<4>(raw, &mut at)? != b"TCP1" { return Err(()); }
    let count = u32::from_le_bytes(take(raw, &mut at)?);
    let mut output = Vec::new();
    for _ in 0..count {
        let id = take::<4>(raw, &mut at)?;
        let n = take::<1>(raw, &mut at)?[0];
        if n > 3 { return Err(()); }
        let price = u64::from_le_bytes(take(raw, &mut at)?);
        let size = i64::from_le_bytes(take(raw, &mut at)?);
        let mut entries = Vec::new();
        for _ in 0..n {
            entries.push(RawMarginTier {
                lower_bound: u64::from_le_bytes(take(raw, &mut at)?),
                max_leverage: take::<1>(raw, &mut at)?[0],
            });
        }
        let table = if n == 0 { None } else {
            Some(MarginTable::try_from(RawMarginTable {
                description: String::new(), tiers: entries,
            }).map_err(|_| ())?)
        };
        let cap = position_leverage_cap(table.as_ref(), price, size);
        output.extend_from_slice(&id);
        output.push(cap);
    }
    if at != raw.len() { return Err(()); }
    Ok(output)
}
fn main() {
    let mut raw = Vec::new();
    if io::stdin().read_to_end(&mut raw).is_err() { std::process::exit(2); }
    match decode(&raw) {
        Ok(out) => { if io::stdout().write_all(&out).is_err() { std::process::exit(2); } }
        Err(()) => std::process::exit(2),
    }
}

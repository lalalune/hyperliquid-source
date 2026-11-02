//! Input-only synthetic scalar client; no expected answers or injected cap.
use node94_margin_risk::{
    CustomIsolatedDecrease, MarginTable, RawMarginTable, RawMarginTier,
    check_custom_isolated_decrease,
};
use std::io::{self, Read, Write};

fn take<const N: usize>(raw: &[u8], at: &mut usize) -> Result<[u8; N], ()> {
    let end = at.checked_add(N).ok_or(())?;
    let value = raw.get(*at..end).ok_or(())?.try_into().map_err(|_| ())?;
    *at = end;
    Ok(value)
}
fn u32_at(raw: &[u8], at: &mut usize) -> Result<u32, ()> {
    Ok(u32::from_le_bytes(take(raw, at)?))
}
fn client(raw: &[u8]) -> Result<Vec<u8>, ()> {
    let mut at = 0;
    if &take::<4>(raw, &mut at)? != b"ILD1" { return Err(()); }
    let count = u32_at(raw, &mut at)?;
    let mut output = Vec::new();
    for _ in 0..count {
        let id = u32_at(raw, &mut at)?;
        let metadata_table_id = u32_at(raw, &mut at)?;
        let position_table_id = u32_at(raw, &mut at)?;
        let position_mode_word = u32_at(raw, &mut at)?;
        let cross_requested = match take::<1>(raw, &mut at)?[0] {
            0 => false, 1 => true, _ => return Err(()),
        };
        let old_leverage = u32_at(raw, &mut at)?;
        let requested_leverage = u32_at(raw, &mut at)?;
        let position_size = i64::from_le_bytes(take(raw, &mut at)?);
        let isolated_margin = i64::from_le_bytes(take(raw, &mut at)?);
        let price_word = u64::from_le_bytes(take(raw, &mut at)?);
        let n = take::<1>(raw, &mut at)?[0];
        if !(1..=3).contains(&n) { return Err(()); }
        let mut tiers = Vec::new();
        for _ in 0..n {
            tiers.push(RawMarginTier {
                lower_bound: u64::from_le_bytes(take(raw, &mut at)?),
                max_leverage: take::<1>(raw, &mut at)?[0],
            });
        }
        let table = MarginTable::try_from(RawMarginTable {
            description: String::new(), tiers,
        }).map_err(|_| ())?;
        let result = check_custom_isolated_decrease(&table, CustomIsolatedDecrease {
            metadata_table_id, position_table_id, position_mode_word,
            cross_requested, old_leverage, requested_leverage,
            position_size, isolated_margin, price_word,
        });
        let (choice, tag, cap) = match result {
            Ok(value) => match value.native_refusal() {
                None => (0_u8, 0_u16, None),
                Some((tag, cap)) => (1, tag, cap),
            },
            // Chosen safe-API error class; no native error tag/byte ABI claimed.
            Err(_) => (2, 0, None),
        };
        output.extend_from_slice(&id.to_le_bytes());
        output.push(choice);
        output.extend_from_slice(&tag.to_le_bytes());
        output.push(u8::from(cap.is_some()));
        // Absent-detail zero is client framing, never native unknown padding.
        output.extend_from_slice(&cap.unwrap_or(0).to_le_bytes());
    }
    if at != raw.len() { return Err(()); }
    Ok(output)
}
fn main() {
    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() { std::process::exit(2); }
    match client(&input) {
        Ok(output) => if io::stdout().write_all(&output).is_err() { std::process::exit(2); },
        Err(()) => std::process::exit(2),
    }
}

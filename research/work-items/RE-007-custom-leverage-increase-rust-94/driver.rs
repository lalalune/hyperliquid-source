//! Synthetic input-only client; framing is chosen policy, never native ABI.
//! Native-absent details are encoded with an explicit presence bit. No expected
//! decision, table maximum, cap value or policy label is supplied as input.
use std::io::{self, Read, Write};
use node94_margin_risk::{
    MarginTable, RawMarginTable, RawMarginTier, CustomLeverageIncrease,
    CustomIncreaseDecision, CustomIncreaseDomainError, check_custom_leverage_increase,
};
fn take<const N: usize>(raw: &[u8], at: &mut usize) -> Result<[u8; N], ()> {
    let end = at.checked_add(N).ok_or(())?;
    let out = raw.get(*at..end).ok_or(())?.try_into().map_err(|_| ())?;
    *at = end;
    Ok(out)
}
fn read_u32(raw: &[u8], at: &mut usize) -> Result<u32, ()> {
    Ok(u32::from_le_bytes(take(raw, at)?))
}
fn client(raw: &[u8]) -> Result<Vec<u8>, ()> {
    let mut at = 0;
    if &take::<4>(raw, &mut at)? != b"LCG1" { return Err(()); }
    let count = read_u32(raw, &mut at)?;
    let mut output = Vec::new();
    for _ in 0..count {
        let id = read_u32(raw, &mut at)?;
        let metadata_table_id = read_u32(raw, &mut at)?;
        let position_table_id = read_u32(raw, &mut at)?;
        let kind_byte = take::<1>(raw, &mut at)?[0];
        let cross_requested = match take::<1>(raw, &mut at)?[0] {
            0 => false, 1 => true, _ => return Err(()),
        };
        let position_mode_word = read_u32(raw, &mut at)?;
        let old_leverage = read_u32(raw, &mut at)?;
        let requested_leverage = read_u32(raw, &mut at)?;
        let price_word = u64::from_le_bytes(take(raw, &mut at)?);
        let position_size = i64::from_le_bytes(take(raw, &mut at)?);
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
        let result = check_custom_leverage_increase(&table, CustomLeverageIncrease {
            metadata_table_id, position_table_id, position_mode_word, old_leverage,
            position_size, requested_leverage, price_word, cross_requested, kind_byte,
        });
        let (choice, tag, cap): (u8, u16, Option<u32>) = match result {
            Ok(CustomIncreaseDecision::EnterCommit) => (0, 0, None),
            Ok(CustomIncreaseDecision::RejectCrossKind) => (1, 0x44, None),
            Ok(CustomIncreaseDecision::RejectOverallMaximum) => (1, 0x43, None),
            Ok(CustomIncreaseDecision::RejectAccountingMode) => (1, 0x45, None),
            Ok(CustomIncreaseDecision::RejectPositionCap { cap }) => (1, 0x50, Some(cap)),
            Err(CustomIncreaseDomainError::BuiltinTableOutsideScope) => (2, 1, None),
            Err(CustomIncreaseDomainError::DifferentPositionTable) => (2, 2, None),
            Err(CustomIncreaseDomainError::InactivePosition) => (2, 3, None),
            Err(CustomIncreaseDomainError::RequestedDecrease) => (2, 4, None),
        };
        output.extend_from_slice(&id.to_le_bytes());
        output.push(choice);
        output.extend_from_slice(&tag.to_le_bytes());
        output.push(u8::from(cap.is_some()));
        // Zero is a client placeholder when presence=false, not a claim about
        // native status+4 or its uninitialized padding on tag43/44/45 paths.
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

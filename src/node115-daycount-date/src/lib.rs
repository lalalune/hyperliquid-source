#![no_std]

#[inline(always)]
const fn year_start(year: u32) -> u32 {
    365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400
}

/// Raw i32 day count to the selected packed-date word; zero denotes failure.
/// This interface states only the observed integer contract, not an original
/// Rust type, crate boundary, panic policy or caller ownership model.
#[unsafe(no_mangle)]
pub extern "C" fn node115_date_from_ce_days(raw: i32) -> u32 {
    let Some(day) = raw.checked_add(365) else { return 0; };
    let cycle = day.div_euclid(146097);
    let remainder = day.rem_euclid(146097) as u32;
    let mut low = 0;
    let mut high = 400;
    while low + 1 < high {
        let middle = (low + high) / 2;
        if year_start(middle) <= remainder { low = middle; } else { high = middle; }
    }
    let year = cycle * 400 + low as i32;
    if !(-262143..=262142).contains(&year) { return 0; }
    let start = year_start(low);
    let ordinal = remainder - start + 1;
    let leap = low % 4 == 0 && (low % 100 != 0 || low == 0);
    let common = if leap { 0 } else { 8 };
    let flags = common | ((start + 3) % 7 + 1);
    let packed = ((year as u32) << 13) | (ordinal << 4) | flags;
    if packed & 0x1ff8 < 0x16e1 { packed } else { 0 }
}

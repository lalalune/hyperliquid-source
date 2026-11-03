#![no_std]

/// New logical projection of only the defined three-byte normal-path stores.
/// These fields and their layout are not the original visitor/result ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projection {
    pub next_cursor: u64,
    pub next_count: u64,
    pub control_words: [u64; 2],
    pub value_bits: [u64; 3],
    pub marker: u8,
}

#[inline(always)]
fn integer_binary64(value: u8) -> u64 {
    if value == 0 { return 0; }
    let n = value as u64;
    let mut top = n;
    let mut exponent = 0;
    while top > 1 { top >>= 1; exponent += 1; }
    ((1023 + exponent) << 52) | ((n - (1 << exponent)) << (52 - exponent))
}

/// Only the nonnull/nonwrapping cursor and count<=MAX-3 cut is qualified.
/// None is our domain refusal, not a claim about native error behavior.
/// Cursor is a numeric coordinate here; the source never dereferences it.
#[inline(always)]
pub fn project(input: [u8; 3], cursor: u64, count: u64) -> Option<Projection> {
    if cursor == 0 { return None; }
    let next_cursor = cursor.checked_add(3)?;
    let next_count = count.checked_add(3)?;
    Some(Projection {
        next_cursor, next_count,
        control_words: [0, 0],
        value_bits: [integer_binary64(input[0]), integer_binary64(input[1]), integer_binary64(input[2])],
        marker: 0,
    })
}

/// Synthetic probe layout: qualified/cursor/count/controls2/values3/marker.
/// Unknown native incoming XMM payloads/padding are excluded, not zero-filled.
/// # Safety
/// out names nine writable aligned exclusive u64 words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_priority_probe(out: *mut u64, cursor: u64, count: u64, first: u8, second: u8, third: u8) {
    let Some(p) = project([first,second,third],cursor,count) else {
        unsafe { out.write_volatile(0); }
        return;
    };
    unsafe {
        out.add(0).write_volatile(1);
        out.add(1).write_volatile(p.next_cursor);
        out.add(2).write_volatile(p.next_count);
        out.add(3).write_volatile(p.control_words[0]);
        out.add(4).write_volatile(p.control_words[1]);
        out.add(5).write_volatile(p.value_bits[0]);
        out.add(6).write_volatile(p.value_bits[1]);
        out.add(7).write_volatile(p.value_bits[2]);
        out.add(8).write_volatile(p.marker as u64);
    }
}

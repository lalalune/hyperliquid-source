#![no_std]

/// Logical request/state protocol, not original formatter/callback ABI.
/// The callback may edit the flag and its own future behavior. Nonzero status
/// stops and is normalized to1. Input remains immutable and callbacks return
/// normally; rendering, unwind and physical vtable identity are unqualified.
#[inline(always)]
pub fn write_lines(input: &[u8], flag: &mut u8, mut callback: impl FnMut(&mut u8, &[u8]) -> u8) -> u8 {
    let mut start = 0;
    while start < input.len() {
        let mut end = start;
        while end < input.len() && unsafe { input.as_ptr().add(end).read_volatile() } != 10 { end += 1; }
        let has_lf = end < input.len();
        if has_lf { end += 1; }
        if *flag != 0 {
            // Materialize our own stack slice; no external constant/helper
            // is needed by the compiled isolated probe.
            let mut indent = [0u8;4];
            for i in 0..4 { unsafe { indent.as_mut_ptr().add(i).write_volatile(32); } }
            if callback(flag,&indent) != 0 { return 1; }
        }
        *flag = has_lf as u8;
        // start<=end<=input.len() follows from the two bounded loops.
        let piece = unsafe { core::slice::from_raw_parts(input.as_ptr().add(start),end-start) };
        if callback(flag,piece) != 0 { return 1; }
        start = end;
    }
    0
}

/// Synthetic event recorder around the SAME generic function.
/// Four-qword events:kind(0input/1indent),offset-or-indentword,length,flag-before.
/// Header:normalized status,final flag,call count. Per-call script4bytes:
/// raw return status,write-flag switch,flag value,reserved. Exhausted script
/// means ordinary success/no flag edit. Scripts can represent changing
/// callback behavior; no original callback identity or real writer is claimed.
/// # Safety
/// Nonaliasing input/script slices are valid <=isizeMAX. out is aligned and
/// exclusive with room for3+8*input_length qwords (at most2 calls per byte).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_newline_probe(out: *mut u64, input: *const u8, length: usize, initial: u8, script: *const u8, script_len: usize) {
    unsafe {
        let bytes = core::slice::from_raw_parts(input,length);
        let mut flag = initial;let mut count = 0;
        let status = write_lines(bytes,&mut flag,|flag,piece| {
            let ptr = piece.as_ptr() as usize;
            let base = input as usize;
            let is_input = ptr >= base && ptr - base < length;
            let mut value = ptr.wrapping_sub(base) as u64;
            if !is_input {
                value = 0;
                for i in 0..4 { value |= (piece.as_ptr().add(i).read_volatile() as u64) << (8*i); }
            }
            let event = out.add(3+4*count);
            event.write_volatile((!is_input) as u64);event.add(1).write_volatile(value);event.add(2).write_volatile(piece.len() as u64);event.add(3).write_volatile(*flag as u64);
            let mut result = 0;
            if count < script_len {
                let action = script.add(4*count);result = action.read_volatile();
                if action.add(1).read_volatile() != 0 { *flag = action.add(2).read_volatile(); }
            }
            count += 1;result
        });
        out.write_volatile(status as u64);out.add(1).write_volatile(flag as u64);out.add(2).write_volatile(count as u64);
    }
}

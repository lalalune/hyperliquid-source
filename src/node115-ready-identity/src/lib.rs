#![no_std]

/// New logical key; no original Rust type or TLS implementation is claimed.
pub struct Key<'a> { pub bytes: &'a [u8], pub word: u32, pub token: u64 }

/// Qualified ready-vector relation; borrow restoration is a scalar result.
/// Input readiness=1, valid nonaliasing slices and nonwrapping vector arithmetic
/// are preconditions. None is our own out-of-domain refusal, not native panic.
#[inline(always)]
pub fn ready_contains<'a>(enabled: u8, counter: u64, rows: impl IntoIterator<Item=Key<'a>>, key: &Key<'_>) -> Option<bool> {
    if enabled != 1 { return Some(false); }
    if counter >= (1u64 << 63) - 1 { return None; }
    for row in rows {
        if row.token != key.token || row.word != key.word || row.bytes.len() != key.bytes.len() { continue; }
        let mut equal = true;
        for i in 0..key.bytes.len() {
            // Both slice lengths are equal and i is in bounds.
            if unsafe { row.bytes.as_ptr().add(i).read_volatile() != key.bytes.as_ptr().add(i).read_volatile() } { equal = false; break; }
        }
        if equal { return Some(true); }
    }
    Some(false)
}

/// Private adapter; construction requires valid nonaliasing raw record slices.
struct RawRows<'a> { data: *const u8, count: usize, index: usize, lifetime: core::marker::PhantomData<&'a [u8]> }
impl<'a> Iterator for RawRows<'a> {
    type Item = Key<'a>;
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.count { return None; }
        unsafe {
            let row = self.data.add(56 * self.index); self.index += 1;
            let ptr = (row as *const u64).read_unaligned() as *const u8;
            let len = (row.add(8) as *const u64).read_unaligned() as usize;
            Some(Key { bytes: core::slice::from_raw_parts(ptr,len), word: (row.add(16) as *const u32).read_unaligned(), token: (row.add(24) as *const u64).read_unaligned() })
        }
    }
}
/// Synthetic probe of the SAME generic safe scan used by callers.
/// # Safety
/// out names3 exclusive writable aligned qwords; key names32 readable bytes;
/// rows names count*56 readable nonwrapping bytes. All encoded pointer/length
/// pairs, including those whose scalar fields differ, are valid nonnull slices
/// of length<=isize::MAX. This is stricter than native's deferred bcmp reads.
/// TLS readiness=1 and no aliasing with output are required. No actual TLS
/// lifecycle or borrow counter mutation/ordering is implemented by this API.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_identity_probe(out: *mut u64, rows: *const u8, count: usize, key: *const u8, counter: u64, enabled: u8) {
    unsafe {
        let k = Key { bytes: core::slice::from_raw_parts((key as *const u64).read_unaligned() as *const u8,(key.add(8) as *const u64).read_unaligned() as usize), word:(key.add(16) as *const u32).read_unaligned(),token:(key.add(24) as *const u64).read_unaligned() };
        let input = RawRows { data:rows,count,index:0,lifetime:core::marker::PhantomData };
        match ready_contains(enabled,counter,input,&k) {
            Some(found) => {out.write_volatile(1);out.add(1).write_volatile(found as u64);out.add(2).write_volatile(counter);}
            None => out.write_volatile(0),
        }
    }
}

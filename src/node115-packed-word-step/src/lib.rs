#![no_std]
use core::sync::atomic::{AtomicU64, Ordering};

/// Observed capacity-prefix word preparation; None is a new API refusal,
/// not the native constructor's panic/allocator/provider behavior.
#[inline(always)]
pub const fn prepare_capacity(capacity: u64) -> Option<u64> {
    if capacity >> 61 != 0 { None } else { Some(capacity * 2) }
}

/// Logical local routes, not original AL/object tags or complete acquisition.
#[repr(u64)]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum WordStep { FlagGate=0, EmptyGate=1, Decremented=2 }

/// Reconstruct only the packed-word CAS loop before the opaque provider.
/// SeqCst is an explicit policy of THIS new API, not a recovered Rust source
/// ordering or a proof of the captured component's concurrency/liveness.
#[inline(always)]
pub fn try_decrement(word: &AtomicU64) -> WordStep {
    let mut observed = word.load(Ordering::SeqCst);
    loop {
        if observed & 1 != 0 { return WordStep::FlagGate; }
        if observed < 2 { return WordStep::EmptyGate; }
        match word.compare_exchange(observed, observed - 2, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return WordStep::Decremented,
            Err(actual) => observed = actual,
        }
    }
}

/// New two-qword probe ABI: prefix-qualified, encoded-word (when qualified).
/// # Safety
/// out names2 writable aligned exclusive u64 words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_permit_init_probe(out:*mut u64, capacity:u64) {
    match prepare_capacity(capacity) {
        Some(word) => unsafe {out.write_volatile(1);out.add(1).write_volatile(word);},
        None => unsafe {out.write_volatile(0);},
    }
}

/// New two-qword probe ABI: local route, subsequently loaded word. Final word
/// comparison is qualified by the finite synthetic schedule, not real races.
/// # Safety
/// out names2 writable aligned exclusive u64 words; word names a valid aligned
/// AtomicU64, nonaliasing output, and adheres to Rust's atomic memory model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_permit_step_probe(out:*mut u64, word:*const AtomicU64) {
    let state = unsafe { &*word };let result = try_decrement(state);
    unsafe {out.write_volatile(result as u64);out.add(1).write_volatile(state.load(Ordering::SeqCst));}
}

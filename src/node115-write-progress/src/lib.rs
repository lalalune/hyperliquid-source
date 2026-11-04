#![no_std]

/// Conditional scalar state at 0x2b7afc0, before scheduling or error conversion.
/// Addresses are raw numeric observations, never dereferenced by this library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub pointer: u64,
    pub remaining: u64,
    pub route: u64,
    pub argument: u64,
    pub inner_state: Option<u8>,
}

pub const CONTINUE: u64 = 0;
pub const COMPLETE: u64 = 1;
pub const PENDING: u64 = 2;
pub const TRANSFORM: u64 = 3;
pub const BOUNDS_FAILURE: u64 = 4;

/// The native qword counter charge on initial entry, not on resume.
pub fn charge(counter: u64, length: u64) -> u64 {
    counter.wrapping_add(length)
}

/// One conditional raw-helper transition. A CONTINUE result returns to the
/// length test; pending resumes at that test without charging again. Inputs
/// stand for helper outputs, not socket activity. For COMPLETE/BOUNDS_FAILURE
/// the argument is unspecified here and reported as zero. For CONTINUE the
/// inner byte has not yet been written, represented by None.
pub fn advance(pointer: u64, remaining: u64, status: u64, value: u64) -> Progress {
    if remaining == 0 {
        return Progress { pointer, remaining, route: COMPLETE, argument: 0, inner_state: Some(1) };
    }
    if status != 0 {
        return if status == 2 {
            Progress { pointer, remaining, route: PENDING, argument: 0, inner_state: Some(3) }
        } else {
            Progress { pointer, remaining, route: TRANSFORM, argument: value, inner_state: Some(1) }
        };
    }
    // Native stores these sentinel fields BEFORE checking subtraction borrow.
    if value > remaining {
        return Progress { pointer: 1, remaining: 0, route: BOUNDS_FAILURE, argument: 0, inner_state: None };
    }
    let next = Progress {
        pointer: pointer.wrapping_add(value), remaining: remaining - value,
        route: CONTINUE, argument: 0, inner_state: None,
    };
    if value == 0 {
        Progress { route: TRANSFORM, argument: 0x1700000003, inner_state: Some(1), ..next }
    } else {
        next
    }
}

/// Validation adapter with an explicit synthetic output layout, not native ABI.
/// # Safety
/// `out` must designate six writable, aligned u64 words, exclusively borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_progress_probe(out: *mut u64, pointer: u64, remaining: u64, status: u64, value: u64, counter: u64) {
    let p = advance(pointer, remaining, status, value);
    unsafe {
        out.add(0).write_volatile(p.pointer);
        out.add(1).write_volatile(p.remaining);
        out.add(2).write_volatile(p.route);
        out.add(3).write_volatile(p.argument);
        out.add(4).write_volatile(p.inner_state.unwrap_or(0) as u64);
        out.add(5).write_volatile(charge(counter, remaining));
    }
}

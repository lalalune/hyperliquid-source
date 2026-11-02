#![no_std]

/// Conditional adjacent-pair invariant only, not a provider or nonce policy.
///
/// # Safety
/// `storage` names capacity initialized u64 words (alignment is not required);
/// count <= capacity,
/// capacity <= isize::MAX / 8, and head < capacity (or both zero).
/// These are preconditions of the observed native paths, not recovered checks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_nonce_ring_is_ordered(
    storage: *const u64, capacity: usize, head: usize, count: usize,
) -> bool {
    if count < 2 { return true; }
    let mut previous = unsafe { core::ptr::read_unaligned(storage.add(head)) };
    let mut index = head;
    let mut remaining = count - 1;
    while remaining != 0 {
        index += 1;
        if index == capacity { index = 0; }
        let current = unsafe { core::ptr::read_unaligned(storage.add(index)) };
        if previous >= current { return false; }
        previous = current;
        remaining -= 1;
    }
    true
}

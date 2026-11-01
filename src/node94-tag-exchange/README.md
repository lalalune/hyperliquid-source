# Node94 atomic tag-byte exchange

`exchange(tag_bits, object, cell)` normalizes the low tag byte to 0, 2 or 1,
then performs one SeqCst atomic swap. It returns full RAX containing the
replaced byte, RCX zero and the numeric original field address `object+16`
with wrapping arithmetic. That number is not used to dereference the cell.

The value replaced by the atomic operation is returned even if another
thread changes the field again before the call finishes. The library uses
safe `AtomicU8` operations and requires byte atomic RMW support. Original
pointers, ABI, flags, faults and other-memory interactions are excluded.

See the [evidence packet](../../research/work-items/RE-004-tag-exchange-rust-94/README.md)
and [proof](../../research/work-items/RE-004-tag-exchange-rust-94/PROOF.md)
for the exact domain, compiler-IR and concurrency qualification.

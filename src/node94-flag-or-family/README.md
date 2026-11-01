# Node94 indexed-OR family

`apply(family, index_bits, load_bias, object, field)` selects a measured
u32 using the low input byte and ORs it into one field value. It reports
full RAX (the selected word), RCX (the load-biased table base) and the
numeric four-byte store address. The supplied Rust field address is not
that numeric address.

All 256 indices of each of the three complete functions are supported.
Their overlapping read windows are stored once as 362 measured words;
these windows are not claimed as logical table extents. No application
meaning is assigned to their words or bits.

This dependency-free safe `no_std` component builds directly with rustc.
See the [evidence packet](../../research/work-items/RE-004-flag-or-family-rust-94/README.md)
and [proof](../../research/work-items/RE-004-flag-or-family-rust-94/PROOF.md)
for the ordinary-memory premises, full relation and reproduction commands.

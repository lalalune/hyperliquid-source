# Node94 global clamp value projection

`initialize(value, state)` replaces all three qwords and returns zero.
The input is one signed runtime-global snapshot. Negative inputs clear
the state; nonnegative inputs produce a scaled/capped first word, a zero
middle word and the unshifted normalized input as the last word.

This dependency-free `no_std`, safe Rust component builds directly with
rustc. It models numeric state, not native globals or their ABI. See
[the evidence packet](../../research/work-items/RE-004-global-clamp-rust-94/README.md)
and [full proof](../../research/work-items/RE-004-global-clamp-rust-94/PROOF.md)
for the closed tail dependency, domain and reproduction commands.

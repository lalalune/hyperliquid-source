# Node94 modular scaled advance

`advance(&mut cursor, end, requested)` reproduces the complete numeric state
transition at `[0x4ea41e0,0x4ea4216)`, including all u64 wrapping behavior and
full returned remainder. The only changed target field is the cursor at +8;
end is the copied entry field at +24. There is no native pointer ABI claim.

For ordinary spans `end-cursor = 88*m`, it advances at most m elements. For
other spans, replacing the modular inverse product by floor division is wrong:
a span of eight with request one advances the numeric cursor by 88. The API
preserves that behavior and does not invent input validation or an end clamp.

The [evidence/proof packet](../../research/work-items/RE-004-scaled-advance-rust-94/README.md)
binds the target, constant identity, field/return relation and independent
quotient-equation expectations. The dependency-free `no_std` library is built
directly as an rlib with a real input-only client using pinned rustc; no external
package, Cargo workspace or invented lockfile is required.

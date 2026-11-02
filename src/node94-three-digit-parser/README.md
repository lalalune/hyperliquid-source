# Node94 strict three-digit parser

`parse(length, bytes)` returns the full original RAX value. Length must be
exactly three; only ASCII `100` through `999` return nonzero. Other lengths
return zero without requiring input bytes. Length three with an unavailable
three-byte prefix returns a distinct new safe `TooShort` refusal.

The explicit length is independent of the supplied prefix length. Extra
bytes are ignored; the library has no four-byte limit. Original pointers,
ABI, faults, flags, other registers and physical access traces are excluded.

This safe `no_std` library builds directly with rustc. The
[evidence packet](../../research/work-items/RE-004-three-digit-parser-rust-94/README.md)
and [proof](../../research/work-items/RE-004-three-digit-parser-rust-94/PROOF.md)
contain the full byte-domain argument and reproduction commands.

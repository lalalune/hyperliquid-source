# Node94 twenty-byte mixer

`mix(prefix, &[u8; 20], [seed0, seed1]) -> u64` reconstructs the returned
RAX value at node94 ELF VA `0x4b27620..0x4b27669`. It reads overlapping
little-endian words at offsets 0, 4, 8 and 12 and folds three complete
unsigned 128-bit products. Every input bit pattern is admitted.

This dependency-free `no_std` library uses only safe Rust. Runtime seed
initialization, pointer ABI and caller purpose are unknown; seeds are explicit
inputs. Stable ordinary input memory is the correspondence premise.

The [evidence packet](../../research/work-items/RE-004-xor20-mixer-rust-94/README.md)
contains the complete static proof, independent frozen oracle, input-only
driver, native comparison commands and actual results. Build it directly with
the packet's pinned compiler command; no workspace/dependency graph is added.

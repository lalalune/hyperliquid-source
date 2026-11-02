# Ordered reversed-record copy, node #94

`lib.rs` is an independently authored, dependency-free, safe `no_std` value
reconstruction of the complete 132-byte leaf `[0x3818d40, 0x3818dc4)` in node #94
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

```rust
pub fn copy_record(arena: &mut [u8], source: usize, destination: usize) -> Option<usize>
```

Both offsets identify 52-byte ranges in one arena. The function performs these
ordered operations, snapshotting each individual block before its store:

| Order | Source offset | Destination offset | Bytes | Byte order |
| --- | ---: | ---: | ---: | --- |
| 1 | 48 | 16 | 4 | unchanged |
| 2 | 32 | 0 | 16 | unchanged |
| 3 | 16 | 20 | 16 | reversed |
| 4 | 0 | 36 | 16 | reversed |

Offsets in the table are relative to the respective record. Overlap is allowed:
a later load observes earlier stores. A whole-source snapshot would change the
answer for some overlapping records. Bytes outside the destination range remain
unchanged. Invalid or overflowing ranges return `None` before any store.

The original leaf takes destination in RDI and source in RSI, returning the
unchanged destination pointer in full RAX. `Some(destination)` is its offset
projection in the supplied arena. This new safe API does not reproduce the raw
pointer ABI or the original behavior on invalid pointers. `None` is a new refusal,
not an observed original error. Qualification uses a 64-bit host; `usize` and
slice admission remain platform-dependent Rust properties.

The correspondence assumes ordinary initialized, readable/writable, stable,
nonwrapping memory and a normal return. Faults, concurrent mutation, MMIO,
instruction/stack-memory aliasing and externally visible intermediate writes are
outside the claim. No original source type, library identity, application purpose,
compiler provenance or target compiled-byte identity is claimed.

The [evidence packet](../../research/work-items/RE-004-reversed-record-copy-rust-94/README.md)
contains the full proof, two decoder exports, FDE/GOT/caller bindings, frozen byte
provenance oracle, native results, and exact replay recipe. The small
`input_only_driver.rs` constructs real byte arenas from input descriptors and
emits the returned offset plus the entire backing arena; it never reads expected
outputs. It is a research client, not part of the `no_std` library.

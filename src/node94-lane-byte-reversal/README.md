# node94 lane byte reversal

Independent, dependency-free safe `no_std` Rust for the complete node94
function `[0x56544a0,0x56544f0)`. It reverses bytes within each of eight
four-byte lanes of a 32-byte entry snapshot. Lanes stay in place; for
example `01 02 03 04 05 06 07 08` becomes `04 03 02 01 08 07 06 05`.

`reverse_lanes(image, base, source, destination, entry_rax)` admits arbitrary
source/destination overlap and unaligned offsets. It samples the complete
source before any store, changes only destination bytes, and returns the
full supplied entry RAX because the native function leaves RAX unchanged.
That projected result does not identify the original source-level signature.

The image and both 32-byte ranges must be nonwrapping and fully mapped in
the supplied slice. Missing ranges return `Err(Unavailable)` before any
write. Correspondence requires stable ordinary data and valid disjoint
code/return control. The API does not reconstruct native pointers, arbitrary
wrapped layouts, faults, MMIO, concurrency, access traces, flags or scratch
R8..R11 results. Numeric images are not claims about OS mapping availability.

Build this standalone component with Rust 1.94.1:

```sh
cargo +1.94.1 check --offline --locked --manifest-path src/node94-lane-byte-reversal/Cargo.toml
```

The input-only standard-library client is separate from the `no_std`
library. Target identity, complete bytes/FDEs, pre-Rust byte-permutation
oracle, alias proof and exact native results are in
[the evidence packet](../../research/work-items/RE-001-lane-byte-reversal-rust-94/README.md).

# Node #94 fixed-record cursor walk

Dependency-free, safe `no_std` reconstruction of linked ELF VA
`[0x3c1d690,0x3c1d6e1)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This standalone crate implements the admitted finite-record relation; it is
not the original pointer ABI or a node build.

`walk(records, &mut cursor, limit)` uses fixed 56-byte records and an exclusive
limit index. Equal entry indices return `Ok(false)` with no cursor change,
even outside the slice. Unequal inputs must satisfy `cursor < limit <= len`;
otherwise `InvalidRange` leaves the cursor unchanged. This refusal policy is
additional to the native routine.

Each visited record advances the cursor before checking that byte 9 equals 2
and byte 0 equals zero. The first failure returns false with the cursor one
past that record. A nonempty passing range returns true with the cursor at
limit. Records at and beyond the limit, and before the starting index, are
not examined. There is no vacuous true result for an empty range.

The correspondence requires contiguous records at stride 0x38, nonwrapping
mapped pointers, and stable node bytes disjoint from cursor/limit storage.
Safe Rust borrows enforce the corresponding disjointness for this API. Full
record slices strengthen native availability, which needs only two node bytes.
Original aliases, wrapped pointers, backward/off-lattice limits, unbounded
native walks, concurrency/MMIO, faults and original ABI are excluded. The
[proof](../../research/work-items/RE-001-cursor-walk-rust-94/PROOF.md) explains
these limits, termination, full native RAX=0/1 and the concrete caller setup.
No field meaning or source-level function identity is claimed.

Build and verify from the repository root using Rust 1.94.1:

```sh
CARGO_TARGET_DIR=work/cursor-walk-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-cursor-walk/Cargo.toml
python3 -O -B research/work-items/RE-001-cursor-walk-rust-94/verify.py \
  --out work/cursor-walk-review
```

The [evidence packet](../../research/work-items/RE-001-cursor-walk-rust-94/README.md)
retains complete bytes/FDEs, independent expectations frozen before Rust,
an input-only driver, repeated native builds and effective corruption controls.
Only newly authored Rust is executed; no captured code or instruction emulator.

# Source/dependency plan for coordinator review

No Rust or Cargo files are created by this plan. The original static freeze is
unchanged. Proposed files after explicit coordinator approval:

* `src/node94-funding-record-storage/Cargo.toml`, actual Cargo-generated lockfile,
  `src/lib.rs`, `tests/returned_records.rs`, and a short component README.
* Packet-local `driver.rs`, validation/comparison scripts and raw build outputs
  in a later chronological phase, separate from this pre-Rust freeze.

The crate is a real standalone library, MIT, edition 2024, minimum Rust 1.94.1,
`publish=false`. It has **no external or path dependencies**, build script,
network access, feature switches or root-workspace edits. It uses only `std`.
The manifest and lockfile will describe the actual crate; no reference source,
placeholder dependency or unmerged component is required.

## Proposed public surface

`Record` contains exactly `key: u64`, `tag: u64`, `payload: u64`.
`apply_returned_records` accepts mutable references to
`BTreeMap<u64, Vec<u64>>` samples and `BTreeMap<u64, u64>` fallbacks, a `u8`
dex byte, and an immutable record slice. It returns unit.

The source uses a sequential record loop: full tag2 breaks; even tags append
through the sample entry; odd tags update the fallback entry only for byte3.
No enclosing state manager, scheduler adapter, parser in the public library,
reset function, count-return API, error enum or economic naming is proposed.
Owned maps are an explicit active-value representation, not a recovered native
struct or B-tree implementation.

## Source validation after approval

1. Read and hash the exact actual crate, manifest, lock, driver and tests before
   building a private copy; require the originals unchanged after the build.
2. Build/test the actual standalone crate offline and locked with Rust 1.94.1;
   run debug and release profiles, formatting and Clippy for the relevant crate.
   Do not install a toolchain or add a dependency. Coordinator controls broader
   repository checks and Git integration.
3. Compile an input-only driver against the crate. The driver reads only frozen
   input frames and invokes the public function; it never reads the expected
   file, oracle, corpus classification or expected-state constants. It writes
   every resulting sample/fallback entry in the canonical protocol.
4. Compare every debug/release output byte against the pre-source expected bytes;
   retain raw outputs, command/status streams and source/toolchain hashes.
   Independently recount expected/completed case IDs and mismatches. Apply
   comparator controls for omitted, changed, duplicated and reordered output.
5. Compile real temporary wrong-source mutants and require mismatches against
   the unchanged frozen corpus. Planned operative alternatives are: no sentinel
   stop; low-byte-only sentinel; stop after processing tag2; odd means tag1 only;
   nonzero dex guard; first fallback wins; replace instead of sample append;
   drop absent sample keys; clear initial state; and clear/canonicalize payload
   bits. A mutant that does not compile is not a killed semantic mutant. Adjust
   syntax to the final source, not the expected corpus, and document equivalent
   or invalid candidates honestly.
6. Independent source/driver/comparator review is required before publication.
   No component gate or native ABI/byte-equivalence claim follows from these
   tests. Allocation/panic/rollback behavior and scheduler coverage stay excluded.

The frozen corpus includes all 256 dex bytes, full-width tag aliases, repeated
and distinct keys, empty/existing sample vectors, existing fallback entries,
unsigned key boundaries, raw payload bit patterns, stop prefixes and long
streams. It targets the documented semantics, not a generic map API.

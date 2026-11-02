# RE-008: combined QC projection source closure

This records the integration of the accepted FD-only four-success group packet
into draft #1509's public head `63e4ac61f9aee72b59e00b14cd4745746dff47bf`.
Source commit `b51f5cb8` retains the existing byte-field and success-assembly
modules and adds `qc_fd_group` to the same real consensus component. The Cargo
manifest, lockfile and dependencies remain unchanged.

## Fresh combined observations

- All three input-only examples were freshly compiled with official pinned
  Rust 1.94.1, offline locked Cargo, denied warnings and overflow checks.
- Each selected example's Cargo dep-info has exactly 13 project Rust sources:
  the 12 crate `src/*.rs` plus that example. The other two examples are excluded.
  Each selection has 15 source/manifest/lock pins. The union is 17 files.
- Byte field: 2,572/2,572 cases at opt0/opt3; six compiled source mutants disagree
  on 516, 3, 515, 513, 769, 1,528 cases per profile.
- FD group: 8/8 frozen cases at opt0/opt3; six compiled source mutants disagree
  on 7, 8, 8, 8, 8, 7 cases per profile. An independent byte reader checks all 40 result
  bytes, retained charge, consumption and suffix.
- Success assembly: 3/3 complete 104-byte frames in debug/release. Its five
  native operand controls remain static analytic controls, not executed captures
  or compiled Rust mutants.
- Fresh native verifiers for all three packets pass. Focused Python passes 9/9;
  component Cargo all-targets passes 48 tests per profile and builds all examples.
- `make doctor`, `make verify`, `make catalogue-check`, `make reproduce`: exit 0.
  Pinned reference checkouts were materialized from existing authenticated local
  stores with lazy fetch disabled. LFS filters were command-local; only verified
  reference index stat metadata was refreshed. No tracked input, pointer, pin,
  persistent configuration or generated catalogue was changed.

`RESULTS.json` pins the combined sources and actual raw receipts. Raw output,
exact argv/exit/stream/executable hashes and compiler dep-info remain under
ignored `work/qc-three-integration/`. The three packet verifiers reproduce
these comparisons using fresh output directories. Binary hashes identify these
actual builds; they are not a target-machine-code comparison.

## Historical records are preserved

The byte-field native packet, byte-field Rust packet and assembly packet are
byte-for-byte unchanged from public head `63e4ac61`. The FD-group packet is
byte-for-byte unchanged from accepted local commit `4330d7a4`. Their original
RESULTS/source pins describe their author phases and are historical, rather
than claims about the expanded combined `lib.rs` or compiler input set. The new
combined source/receipt record supplies that exact-tree qualification without
rewriting prior evidence or relabeling prior failures.

## Scope

These are three independent, bounded projections. The FD group covers only its
mode 1 four-FD-word success domain: 36 wire bytes, 32 charged units, 40 helper-result
bytes. Its vectors describe conditional helper-entry states, without claiming
that every row is reachable after earlier QC consumers. The byte field remains
conditional on prior successes; assembly still receives successful helper-output
snapshots and separately credited tag/recovery context. No complete QC row,
failure-family, original ABI/lifetime, native store timing, cryptographic
validity or captured-runtime equivalence is established. No captured executable
was run or emulated. Full repository `make test` remains pending coordinator
integration. All full component gates remain false.

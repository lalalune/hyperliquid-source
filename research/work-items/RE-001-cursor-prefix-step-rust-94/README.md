# RE-001: reconstruct the node #94 signed-prefix cursor transition

- Component: foundation; bounded RE-001 byte/FDE/data-flow work.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline: main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no unlicensed
  inferred source implementation was opened or copied.
- Included: the complete 82-byte state transition, exact FDE/body/field bindings,
  full direct-call and relocation census, independent safe Rust and frozen oracle.
- Excluded: marker meanings, source identity, dispatcher/table provenance, native
  ABI/fault behavior, whole-node equivalence and component gate completion.

The preceding `foundation-cursor-state-machine-94` packet established static
behavior and explicitly left Rust unimplemented. Its precision note correctly
warned that the length word is read after a counter store. This contribution
implements that ordering with a safe byte-image API, including aliases, rather
than assuming that an entry prefix snapshot remains unchanged. Historical
packet files remain unchanged.

## Result and proof

`src/node94-cursor-prefix-step` is a standalone, dependency-free `no_std` crate
with `forbid(unsafe_code)`. The [proof](PROOF.md) derives all three paths:
zero flag stores 0x67; nonzero flag/counter unsigned <=1 stores 0x50; otherwise
counter decreases by 2, then a signed big-endian i16 prefix advances the cursor
by prefix+2 modulo 2^64. No flag 0/1 invariant, signed-counter interpretation or
nonnegative length assumption is introduced. RAX is described as unchanged,
the loaded counter, or the new cursor, without inferring a source return type.

The memory API maps image byte i to base+i and uses a checked state offset.
It preserves prefix aliases with state, including the counter's just-written
bytes and prefixes straddling either counter boundary. The resulting cursor
need not remain in the image; it is not dereferenced again. The explicit safe
refusal policy rejects invalid image/state/prefix ranges before writes. This
differs from a native fault, which can occur after a counter store. The proof
separates this policy from successful-path correspondence under ordinary,
stable, mapped memory. Concurrency, MMIO, fault order and other register state
remain excluded; there is no generic machine interpreter or captured execution.

## Target and data bindings

The full artifact digest is checked before interpreting structural evidence.
Both GNU and Apple LLVM decode the same complete 19-instruction / 82-byte body
at linked VA `[0x47d6b90,0x47d6be2)`, file offset `0x47d5b90`. Body SHA-256:
`efae6e7037a52d6bbfdea1342560d793424130881ca9446bc9462526cd4164ba`.
All file offsets are resolved through sections, without a guessed loader rebase.

The FDE at `.eh_frame+0x21c9d0` ends exactly at 0x47d6be2. Full decoding of
3 CIEs and 121,299 FDEs finds only this FDE overlapping the body. The raw FDE,
shared CIE, complete-inventory hash and independent GNU frame export are
retained. Fourteen `int3` padding bytes follow; they are not counted as code.
The entry is the flag comparison, without `endbr64`.

The complete 70,370,352-byte `.text` E8 scan finds zero direct callers. This
negative result does not cover indirect calls or tail jumps. The leaf has no
internal calls or static constant-table reads. Its data operands bind the flag
byte +0x1f0, counter qword +0x1e0, cursor qword +0x1d0, marker byte +0x1f3, and
the two bytes reached through the cursor. Full raw body bytes preserve their
widths and load/store order.

All 80,300 RELA records are scanned, without filtering away non-relative kinds.
Exactly 15 records name the entry, each with info=8 and addend=0x47d6b90:
slots 0x5721d88 through 0x5728d88, spaced 0x800 apart. Each file slot is eight
zero bytes in `.data.rel.ro`; exact records and raw slot bytes are bound.
Runtime relocation would supply the target address. The spacing and locations
are observations, not proof of a named dispatch table or identified consumers.
`static/records.json` and the exact raw decoder/frame exports retain these facts.

## Independent oracle and comparison

The immutable-image oracle was frozen before any Rust source existed. It reads
the entry fields, classifies the path, and models the advance prefix by selecting
bytes from an overlay of counter-2 on the entry image. It computes the signed
big-endian value mathematically and constructs the final image by field
replacement. It does not import the historical model, Rust or an instruction
emulator. `fixtures/freeze.json` binds source, raw inputs/expectations and their
deterministic gzip representations. Ordinary verification regenerates them;
`--freeze` refuses to run after the Rust component exists.

The 4,646 frozen cases cover 677 flag-marker and 700 counter-marker outcomes;
2,155 advances, of which 313 have prefix/counter overlap; and 1,114 refusals
(525 image-range, 508 state-bounds and 81 prefix-bounds). Cases include zero,
one and high-bit counters, all flag classes, both endian byte positions,
signed-prefix boundaries, every counter-overlap offset, cursor-field overlap,
exact/short images, huge state offsets, image endpoints at u64::MAX, and cursor
results outside the image or wrapping. This is finite corroboration of the
full-input static relation, not exhaustive enumeration of every memory image.

The input-only native client receives only base, state offset and initial bytes.
It reports the result/RAX relation and a canonical list of every changed image
byte. It compares every input/output byte to form that list; omitted indices
mean unchanged, not masked. Thus inputs plus exact output reconstruct complete
final images, and equality checks all observed memory effects without masks.

All 4,646 cases match at opt0 and opt3, each built/run twice (18,584 comparisons).
The rlib and client hashes match within repeated builds at each optimization.
All 23 compiled mutants exit normally and differ observably. Notable controls:
reading an entry prefix snapshot instead of the updated bytes gives 85
mismatches; rejecting aliases gives 313; storing the counter before rejection
gives 81; wrongly requiring the next cursor inside the image gives 1,221;
saturating cursor arithmetic gives 575. Other controls cover signed counter
comparison, byte order/sign extension, marker writes, counter decrement,
exact boundaries, state-offset truncation and all RAX cases.

There are 55 static corruption controls and 4 comparator controls. Whole-target
corruption is rejected at identity; other controls bypass only that outer gate
to reach body, FDE, CIE, padding, extra call-pattern, raw-slot and relocation
checks. The complete verifier passed under Python `-O`, with explicit exception
checks. No crashing/noncompiling mutant is counted. `native/result.json` gives
counts and first witnesses; `native/commands.json` retains every native compile
command and exit status. One deterministic `native/raw-streams.json.gz` preserves
all 27 exact stdout streams with original byte counts and SHA-256 values.

## Reproduce

Working directory: repository root with pinned artifacts materialized. Validation
used macOS ARM64, Python 3.14.3, rustc 1.94.1, GNU objdump 2.47.20260726 and
Apple LLVM 17.0.0. Exact versions are in `logs/tool-versions.log`. Native builds
use edition2024, codegen-units=1, checked overflow, panic=abort, debuginfo=0,
remapped source paths and warnings denied. No third-party Rust dependencies,
target execution, emulator, node/network/chain/key operation or paid service.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -B research/work-items/RE-001-cursor-prefix-step-rust-94/oracle.py
python3 -O -B research/work-items/RE-001-cursor-prefix-step-rust-94/verify.py \
  --out work/cursor-prefix-review
python3 -B research/work-items/RE-001-cursor-prefix-step-rust-94/verify.py --check-archive
CARGO_TARGET_DIR=work/cursor-prefix-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-cursor-prefix-step/Cargo.toml
python3 -B tools/foundation_cursor_state_machine.py \
  --check research/work-items/foundation-cursor-state-machine-94/evidence.json
python3 -B -m unittest tests.test_foundation_cursor_state_machine -v
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-001-cursor-prefix-step-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

The verifier requires a fresh output directory. `GNU_OBJDUMP`, `LLVM_OBJDUMP`
and `--rustc` select tool paths; exact retained text equality requires the
recorded decoder versions. Repository checks, all seven focused predecessor
tests, the predecessor checker, offline Cargo and rustfmt pass. This worker
did not duplicate the full repository test sweep and claims no full-suite or
hosted CI result. All native/compiler/control runs succeeded without repairs.

`overlap.json` retains initial/live public PR and issue inventories and 30 recent
merges: 69 PRs initially, 74 on final recheck, zero issues, no address/semantic
match. Source search found no Rust implementation; only the preceding static
packet and checker covered the body. No imported evidence, pins, global config,
progress files or completion gates changed. The bounded transition is recovered;
what the state/markers mean and how the 15 relocated entries are used remain
unknown.

# RE-001: gated 48-byte block selection and overlapping copy

This closes the unimplemented Rust gap in `foundation-gated-block-copy-94` for
node #94 ELF VA `[0x4ff8b30,0x4ff8b9c)`. The independent safe `no_std` component
selects between two 48-byte blocks using a flag, a wrapping i32 decrement with
signed bound comparison, and a conditionally read gate byte. It preserves input
snapshots for arbitrary admitted source/destination overlap and returns the
destination offset corresponding to raw RAX.

The complete target is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; pinned reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred unlicensed source was
neither read nor copied. New source and evidence code are independently authored;
raw disassembly retains original artifact rights. Component `foundation`, task
RE-001. No progress gate, imported evidence or pin changes.

## Established relation and limits

[PROOF.md](PROOF.md) derives the relation from the entire body, including the
signed overflow corner at index `i32::MIN`, the exact equality boundary, skipped
index/gate accesses and all-loads-before-stores ordering. The gate is byte 24 of
the preferred payload and is copied as data. Any nonzero flag/gate passes;
there is no invented valid-index range or 0/1-only premise.

`src/node94-gated-block-copy` takes one mutable image with offsets. Only actual
path accesses must fit; an unusable index offset can succeed when flag is zero,
and fallback-only storage can succeed without a mapped gate. Invalid used
ranges are refused before any write. This is a safe memory-image projection,
not the native pointer ABI or a claim about fault/volatile/concurrent/wrapping
address behavior. The function/source type and meanings of the fields remain
unknown. No native target differential, machine-code equality or whole-node
reconstruction is claimed.

## Static closure

`static/records.json` binds the 108-byte, 25-instruction body and seven complete
caller FDEs (39,891 bytes, 8,263 instructions). The full inventory contains
121,299 FDEs and three CIEs; each claimed window has exactly one overlapping
FDE. Exact raw FDEs and both used CIEs are checked. GNU and LLVM independently
decode complete windows with identical byte partitions. The four outside-body
padding bytes are separately checked.

The entire 70,370,352-byte `.text` E8 scan returns eight sites, all at decoded
caller boundaries. All 80,300 RELA entries are scanned; no addend equals this entry address.
The body has no calls or branches outside the bound leaf and no RIP-relative
static data operand: constants and offsets are immediate bytes. Full caller bytes establish incoming edges, while caller
semantics, other calls and other data dependencies are outside this leaf claim.
The proof includes concrete caller setup at `0x5023e7c..0x5023e9f` and
`0x5027f8c..0x5027fae`. The scans do not exclude indirect/computed references.

## Independent comparison

`oracle.py` computes the modular signed selection in arbitrary-precision
arithmetic and forms the final image pointwise from immutable entry bytes.
It is not an instruction interpreter and does not use captured execution.
`fixtures/freeze.json` records hashes, a timestamp and the successful guard
requiring the new Rust source directory to be absent at freeze time.
The input-only client cannot read expected outputs. Every changed byte is
reported; omitted bytes are required unchanged, so the sparse format is
lossless and no normalization mask is applied.

Results and replay commands follow in the validation section below.

## Validation

- 5,137 frozen cases, each run on native opt0 and opt3 builds, repeated twice:
  20,548 comparisons, zero mismatches. Each optimization level's repeated rlib
  and executable hashes are identical.
- 23 actually compiled mutants exit successfully and differ from frozen outputs.
  Witnesses include wrapping-vs-saturating decrement (105 cases), unsigned bound
  comparison (872), strict inequality (805), eager index access (20), eager gate
  access (146), blanket struct availability (270), and streaming overlap (446).
- 56 static corruptions reject, including every body instruction, all direct
  callsites, caller setup, exact FDE extents, both CIEs, external padding, an
  injected naming relocation and an extra E8 candidate. Apart from the dedicated
  identity control, these run below the whole-target hash gate. Four comparator
  controls reject changed value, missing row, duplicate row and reordered rows.
- The predecessor checker and all eight focused tests pass. `make doctor verify
  catalogue-check reproduce`, offline locked Cargo check, rustfmt and archive
  integrity checks pass. No full repository test sweep was run for this packet;
  its independent parent-run sweep is not claimed as this contribution's result.

`native/result.json` retains exact compiler/platform versions, source hashes,
artifact hashes, comparison fields and all mutation witnesses.
`native/commands.json` retains all compile commands and stdout/stderr.
`native/raw-streams.json.gz` is one deterministic lossless archive of 27 exact
stdout streams, retaining each label, original byte count and SHA-256. Schema 2
uses a shared dictionary of complete lines and per-stream line indices: joining
those lines reconstructs exact stdout, including newlines. `verify.py
--check-archive` reconstructs and hashes every stream. This packaging reduced
13,401,297 bytes to 3,503,419 bytes without recomputing outputs or changing source,
inputs or expectations; `native/packing.json` binds both archives.

Two setup/checker issues are retained honestly in `logs/build-note.log`:
Cargo initially lacked rustc on PATH, and an initial static mutation was rejected
by the FDE decoder before the dedicated CIE check. The latter stopped before
native compilation. The CIE binding check now precedes decoding, and the entire
native verifier passed in a fresh directory. Neither event changed Rust logic
or frozen oracle data.

## Reproduce

Run from the repository root; the native verifier requires Python 3, GNU and
LLVM objdump, and installed Rust 1.94.1. It executes only the new Rust client.
Use a fresh ignored output directory:

```sh
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/oracle.py
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/verify.py --out work/gated-copy-replay
python3 -O research/work-items/RE-001-gated-block-copy-rust-94/verify.py --check-archive
python3 -O tools/foundation_gated_block_copy.py --check research/work-items/foundation-gated-block-copy-94/evidence.json
python3 -m unittest tests.test_foundation_gated_block_copy -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --locked --manifest-path src/node94-gated-block-copy/Cargo.toml
(cd research/work-items/RE-001-gated-block-copy-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

`GNU_OBJDUMP`, `LLVM_OBJDUMP` and verifier `--rustc` override local executable
paths. `COMMANDS.md` records collection/history details. Frozen fixtures can be
regenerated in memory and checked; `--freeze` intentionally refuses once the
source directory exists. `MANIFEST.sha256` binds the packet, source and reused
ELF/FDE parsers plus predecessor checker/test.

## Overlap and remaining work

`overlap.json` retains live open PR, issue and recent merge inventories before
selection and before commit. No competing address/semantic claim was found;
existing static predecessor work is acknowledged above. Parent reservations at
`0x54ccfb0`, `0x50e69f0`, `0x538c820` and `0x5422e70` are excluded.
This resolves only the bounded leaf. Caller purposes, record identities and
integration with a whole-node build remain unknown and are not acceptance gates
advanced by this packet.

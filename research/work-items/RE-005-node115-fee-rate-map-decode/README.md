# RE-005: node #115 FeeRateMapSerde prefix decoder

This packet closes the decoder question left by the [existing encoder packet](../RE-005-node115-fee-rate-map-wire/README.md). The [codec component](../../../src/node115-fee-rate-map-codec/README.md) gains a fresh-reader prefix decoder that returns four binary64 words, or a typed error/refusal, together with consumed bytes and remaining depth. The existing encoder remains a separate operation. This decoder accepts more than the encoder's 37-byte output: notably, a binary payload of at least four bytes succeeds using its first four unsigned byte values.

The target is Linux x86-64 node #115, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. Source admission used main `05bc2de303c05525b71e7e257426e741bc66a390`. The retained 31 complete bodies total 8,850 bytes and 2,192 GNU instruction rows. These are evidence extents, not newly reconstructed byte coverage, byte-comparison windows or whole-function equivalence.

## Read the contract

[API-CONTRACT.md](API-CONTRACT.md) is the sealed pre-source authoring contract. Its prospective language describes that earlier stage; actual implementation/qualification results belong in [VALIDATION.md](VALIDATION.md). [PROOF.md](PROOF.md) explains the complete ordinary marker partition and state changes, [FLOATING-POINT.md](FLOATING-POINT.md) the exact numeric words, and [UTF8.md](UTF8.md) the string-validity predicate.

The byte-exact historical [independent native contract](authorship/INDEPENDENT-CONTRACT.md), [UTF-8 derivation](authorship/UTF8-PREDICATE.md) and [pre-source FP proof](floating-proof/PRE-SOURCE-PROOF.md) are retained for authorship review. Historical workspace references in those documents are provenance, not reproduction inputs. The active public bindings are the files linked here. The [scalar arithmetic checker](floating-proof/check_manual_math.py) uses its unchanged [originally named witness file](floating-proof/MANUAL-WITNESSES-v1.json).

The API starts with no cached marker. It does not require the entire slice to be consumed. Important distinctions are:

- An array succeeds after four numeric values only when its declared count is four. A larger array fails after its fourth successful value without reading extras.
- A binary payload consumes its entire declared payload before using the first four bytes. Its depth is unchanged.
- A short fixed-width read consumes the remaining suffix; an insufficient declared binary/string payload leaves that payload unread after its header.
- Array/map/extension depth 0 is refused only when the relevant guard is reached after a complete header. This safe `PanicBoundary` is not a returned native error or an implementation of panic behavior.
- Error paths do not share one rollback rule. Short arrays and element errors retain the depth decrement; four successful values restore it even for excess-count error. Maps retain the decrement; extensions restore it after their rejecting visitor returns.

The returned error enums intentionally omit diagnostic strings, inactive fields, allocator ownership, exact UTF-8 error offsets and native ABI layout.

## Evidence and chronology

The concrete wrapper is `0x27667a0..0x2766800`; it supplies the 15-byte name to `0x17c4630..0x17c550e`. The special `_ExtStruct` branch is not reachable from that wrapper. Full body/FDE/CIE/operand/data/import bindings are in [obligations.json](obligations.json), with fresh GNU exports and records under [observed/](observed/records.json). The same captured image and GNU decoder underlie the manual reviews; this is one native evidence lineage, not an independent runtime oracle.

The925 [manual JSON cases](manual-pre-source.json) and 62 [scalar JSON witnesses](scalar-pre-source.json) were authored and frozen before decoder source. They did not come from executing a reference decoder, the captured program or the new source. The manual set includes all 256 single-marker inputs plus state, truncation, depth and UTF-8 boundaries; that partition does not cover all byte strings. The scalar set covers integer rounding boundaries, binary32 classes and raw binary64 words.

The [manual TSV](manual-cases.tsv) and [scalar TSV](scalar-cases.tsv) are later, post-source transport projections of those frozen expectations. The scalar projection embeds each unchanged numeric witness in one array position with three zero values. The TSV serialization/embedding was not frozen before source, and must not be described as such. [VALIDATION.md](VALIDATION.md) records the projection checks and actual executions.

## Reproduce the scoped checks

Use the repository's authenticated artifact, installed GNU objdump, Python and Rust1.95.0. Run from the repository root, with fresh output directories:

```sh
python3 -I -B -S research/work-items/RE-005-node115-fee-rate-map-decode/controls.py \
  --collector-sha256 38a8d69bc3ce5aa4d23b439f4179331153f72fd3a5095fdfe0c3c0bd2d4f5e55 \
  --target artifacts/node/115/hl-node --output work/fee-rate-controls

python3 -I -B -S research/work-items/RE-005-node115-fee-rate-map-decode/collect.py \
  --target artifacts/node/115/hl-node --objdump /absolute/path/to/GNU/objdump \
  --output work/fee-rate-native --check research/work-items/RE-005-node115-fee-rate-map-decode/observed

cargo +1.95.0 test --offline --locked \
  --manifest-path src/node115-fee-rate-map-codec/Cargo.toml --test frozen_decoder
```

The static controls mutate real operand/data/CFI/relocation bytes below the outer digest guard, and separately exercise re-guarded call/RIP bindings and mocked failure accounting. They do not evaluate instructions or establish decoder semantics by their rejection. The collector authenticates the entire input before output/tool use, disassembles only bounded full bodies from a private non-executable snapshot, and requires exact raw bytes and instruction partitions. Replay permits only declared GNU tool/version provenance differences; native exports and semantic records must agree exactly.

The focused component test calls independently authored Rust against frozen expectations. It does not run captured code. A Linux rlib build, if recorded separately, is a library compilation rather than a node build or execution.

## Limits and prior credit

The prior encoder and its native writer/finalizer proof remain credited. Shared UTF-8, diagnostic and drop helpers are dependencies, not discoveries of new coverage. Numeric behavior is conditional on documented Intel SSE2 semantics, RN-even, DAZ=0, FTZ=0 and masked exceptions; native runtime controls were not measured. Required opaque calls must return normally and preserve valid disjoint input/reader/result/frame storage outside their declared outputs.

This is a fresh-reader value/state projection, not arbitrary cached-state decoding, rendered diagnostics, allocation/reclamation, panic/unwind equivalence, a native ABI, fee-field units, fee-state integration or whole-ELF equivalence. No captured binary, emulator or instruction interpreter is run. Full `make test` and hosted CI are not claimed by these scoped commands. All 92 component acceptance gates remain false.

The next question is which state-owning caller consumes these four words and what each field means. That requires its own complete caller/data evidence; neither field names nor fee units follow from this wire projection.

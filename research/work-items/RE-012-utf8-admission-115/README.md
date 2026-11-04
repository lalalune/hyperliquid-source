# RE-012: complete shared byte validator and safe UTF-8 projection

Target node #115 Linux x86-64, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; foundation supporting
startup/output validation (RE-012) and selected serialization callers.
ELF VAs, no rebasing or normalization. New source/docs MIT. No unlicensed
inferred source or copied public validator implementation was used.

## Original gap and bounded outcome

The base's RE-015-config-path-115, RE-005-node115-chain-origin-writers and
RE-003-node115-priority-prefix-dl-route packets explicitly leave `0x16815e0`
as a byte-validation boundary. This packet closes its complete normal logical
span-validation contract and adds independently authored safe Rust. It does
not claim those callers' full contracts or integration into a source-built node.

The whole FDE is `0x16815e0..0x16817d7`, 503 bytes. records.json retains its
exact hash, complete FDE/CIE bytes, branch rows, instruction operands and the
256-byte width table at `0x46ebe7`. GNU and LLVM full-body partitions agree
with Capstone; GNU readelf independently checks the extent. Table contents:
ASCII width1; C2..DF width2; E0..EF width3; F0..F4 width4; all other bytes width0.
This is measured data, not an assumed public dependency revision.

## Established logical relation

The leaf consumes a disjoint, valid input span. It scans ASCII directly and
with aligned two-qword high-bit-mask checks. The `0x8080808080808080` mask
admits a 16-byte block only if every byte is ASCII; the length-minus-15 guard
keeps both loads within the span. The safe implementation scans those same
bytes individually. No target instruction evaluator is used for this reasoning.

For a non-ASCII lead, the table chooses width2/3/4. Width0 rejects one byte.
Every continuation must be 80..BF, with the additional first-continuation
bounds: E0 requires A0..BF, ED requires 80..9F, F0 requires 90..BF and F4
requires 80..8F. These are pinned signed/unsigned comparisons at
0x16816df, 0x168170d, 0x1681729, 0x1681738 and adjacent branch anchors.
They reject overlong encodings, surrogate code points and values above
U+10FFFF. This interpretation is checked against an independent strict UTF-8
reference rather than inferred only from source-path text.

If the span ends before a required continuation, the failure has no error
length. If a present byte is invalid, the error length is the number of
preceding bytes in that invalid sequence (1, 2 or 3). The failure position
stays at the initial lead, not the location of the offending continuation.
The order is material: a missing later byte is truncation only after earlier
present bytes have passed their own bounds.

At `0x16817a7`, success stores the original pointer at output+8, input count
at +16 and raw tag0 at +0. Failure stores the valid-prefix count at +8,
presence byte at +16, active bad-sequence length at +17 when present, and
raw tag1 at +0. The missing-length route does not establish a meaningful
value for the inactive +17 byte. New Rust deliberately exposes Option<u8>
and safe indices, with no native ABI or padding claim.

## Actual output-preparation consumers

The RELATIVE writer at slot `0x64dfca8` names this exact FDE. At
`0x1502153` in the path-preparation adapter, the returned span from its
preceding opaque helper is passed to this validator; raw result DWORD1
skips adopting that span, while a non-one result loads the validated
pointer/length from +8/+16 into the retained path pair. The output adapter
repeats this branch shape at `0x15025dc`. Both actual call/branch windows
and the relocation writer are frozen in scope.json and freshly checked.
This establishes the validator result convention at real node consumers;
prior interpretation of a generic byte gate alone could not justify it.
The preceding span producer, OS-path semantics and whole consumers remain
separate boundaries.

## Qualification and provenance

The dependency-free library lives at `src/node115-utf8-admission`. qualify.py
first authenticates/reproduces the native obligations, checks all 256 width
entries against the above ranges, then builds a deterministic deduplicated
corpus: all zero/one/two-byte inputs, continuation-boundary classes for long
sequences, ASCII prefix/alignment cases, and seeded random spans. CPython's
strict UTF-8 codec independently supplies the expected error start/end;
unexpected-end maps to absent error length. The corpus and expected hashes,
actual compiler version, native-host outputs and witnesses are retained.

**The oracle corpus was frozen after initial Rust source authoring.** It is
not represented as pre-production expectations. The reference codec is a
separate implementation, while the mapping from target instructions remains
same-author static reasoning, not an independent peer or native execution.
Rust opt0/opt3 runs are compared in full. Five actually compiled source
mutations cover accepting 0x80 as ASCII, overlong C1 leads, surrogate allowance,
values beyond F4's bound and incorrect truncation lengths. Every mutant must
return normally and differ on an explicit recorded input.

The packet verifier reproduces every retained record and raw native listing,
refuses changed capture identity, and changes one actual byte per instruction
anchor plus the width-table anchor with the whole-file digest gate bypassed
only for those narrow negative controls. This is not a claim to reject all
possible mutations or to execute altered captured instructions.

```
python3 -B research/work-items/RE-012-utf8-admission-115/verify.py
python3 -B research/work-items/RE-012-utf8-admission-115/qualify.py work/utf8-fresh /absolute/path/to/rustc-1.95.0
cargo +1.95.0 build --offline --locked --manifest-path src/node115-utf8-admission/Cargo.toml
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-utf8-admission/Cargo.toml
make doctor verify catalogue-check reproduce
```

Actual build/qualification counts, initial environment failures, their
remediation, and repository results belong in validation.json. A first corpus
contained duplicate rows; final qualification removes duplicates and retains
the earlier logs as exploratory results, not extra tests or coverage.

## Limits

No captured execution/emulation, live I/O or compiled-byte equivalence. Linux
code may be built but is not executed on this macOS host. Native pointer
aliasing, invalid spans, inactive result bytes, original compiler/dependency
identity, caller behavior, full node integration and every full-scope gate
remain unclosed. This is a common dependency primitive, not private-code byte
credit. Next: bind one path/output consumer's tag checks and byte-span lifetime
before composing it into a complete source-built path adapter.

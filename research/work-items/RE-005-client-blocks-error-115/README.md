# RE-005: complete ClientBlocksError logical payload

Target Linux x86-64 node #115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; serialization/RE-005.
New code MIT; no inferred unlicensed reference source copied.

## Gap and actual selected type

The existing response-record packet implements the scalar payload under
response variant2, leaving the other payloads open. This change reconstructs
one different complete logical type: `ClientBlocksError`, named by the actual
17-byte diagnostic literal at0x93c560. It is reached after outer response
variant1 selects nested Err tag1 at0x5aac95b..0x5aac9ec. The new API starts
exactly at that nested error payload, so neither outer tag is read or charged
again. It does not pretend to decode the successful container or whole response.

The complete parent FDE0x5aac7c0..0x5aacc22 is reused context, with new
interpretation bounded to0x5aac9ec..0x5aacbcf and shared normal/error stores.
Its u32 call0x5aac9f2 reads an index. Values>6 take the type-bound invalid-index
path0x5aacb32. For0..6, a signed relative table at0x939f28 resolves to
0x5aaca29,0x5aacadc,0x5aaca2b,0x5aacb28,0x5aacad2,0x5aacb53,0x5aacb91.
This establishes rawindices0/2/3/4 are unit variants and1/5/6 each read two
u64 values in order. No semantic names or units are invented for these fields.
The second read begins only after first success. Every scalar error routes
the active error fields to the parent error result; failure is distinct from a
successfully decoded ClientBlocksError value, which is itself an outer Err.

The index is logically charged4; pair cases normally charge20 total,
regardless of encoded byte lengths. Count overflow fails without a new store;
otherwise over-limit refusal retains the updated charge and no input advance.
Actual short u32/u64 paths commit marker consumption before classifying errors;
fast paths preserve that marker on truncated/invalid forms. Nonminimal scalar
representations are accepted. The authentic reader helpers, dispatch tables
and RELATIVE bindings are all preserved; their established primitive behavior
is reused and explicitly credited, not new primitive reconstruction.

## Implementation and evidence

`src/node115-client-blocks-error/` supplies a dependency-authentic no_std
library with a safe rawindex/optional-pair result. It uses the unchanged
MIT u64 reader through the existing main adapter. The MIT logical u32 reader
is copied unchanged and credited from the main Request implementation; there
is no fabricated Cargo graph or guessed registry version. Allocation, padding,
original native enum niches and inactive result bytes are deliberately excluded.

The packet authenticates six complete FDEs (parent plus reader/error helpers),
whole bodies, unwind records, direct/indirect calls/branches, helper RELA writers,
reader dispatch tables, the seven-way table and exact type diagnostic.
GNU/LLVM/Capstone partition every byte, readelf confirms complete extents.
Each real instruction/data anchor is corrupted below only the full-file digest
check; wrong and truncated artifact identities are separately rejected.
`records.json`, native exports, `scope.json` and validation.json retain counts.
No mask, target execution or captured-instruction interpreter is used.

Before the new Rust directory existed, `oracle.py` froze464,234 cases.
The expectation is static scalar mathematics with explicit target-bound
variant arity/table interpretation, never a run of the production reader.
This is same-author interpretation, not a native execution oracle or peer review.
It covers all seven indices/invalid indices, canonical and nonminimal tags,
both scalar widths, every prefix of representative pairs, all invalid markers,
fast/short paths, total charges and overflow boundaries. The original frozen
34MB table is retained in ignored work; the committed `cases.tsv.gz.hex` is
lossless gzip(mtime0) encoded as hex. Its decompression reproduces exactly the
pre-Rust fixture hash in freeze.json; no row/expectation was altered during
compression. Reproduction uses Python standard-library gzip, not an install hook.

Actual Cargo debug/release probes each match every result/cursor/charge row.
Six actually compiled mutants terminate normally and differ: wrong tag charge,
omitted count store, rejected variant6, wrong pair arity selection, swapped
pair order and omitted second read. qualification.json retains first witnesses,
source/compiler/output identities. The lossless fixture replay was rerun after
packing. Host and x86-64 Linux release rlib builds, fmt and clippy -D warnings
pass; Linux target code/captured code is never run. Repository checks are in
validation.json; unchanged583-file base qualification is reused with25 explicit
skips, not a new complete-suite run. Hosted CI is not claimed.

```
source work/environment/new-three-env.sh
python3 -B research/work-items/RE-005-client-blocks-error-115/verify.py
python3 -B research/work-items/RE-005-client-blocks-error-115/qualify.py work/client-blocks-error-replay
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-client-blocks-error/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-client-blocks-error/Cargo.toml -- -D warnings
make doctor verify catalogue-check reproduce
```

Full response envelopes/containers, inferred field meaning, raw modes, aliasing,
ABI/padding, diagnostic formatting/unwinding, full original dependency lock,
compiled-byte identity and integrated-node compatibility remain open.
All92 gates and byte-comparison totals stay unchanged. Next: recover the
separate successful-container payload, then compose the real response decoder.

# RE-005: node #115 two-scalar / fixed 2048-byte bulk record

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; serialization / RE-005.
All addresses are ELF VAs, without rebasing or byte normalization. New code and
research are MIT. Existing MIT scalar code is reused as a real local Cargo
dependency; no unlicensed inferred source or fabricated helper is involved.

## Gap and complete selected type

The existing field1-5 caller-argument packet is static-only: it identifies the
bulk wrapper but supplies no Rust record decoder. This change reconstructs its
complete logical prefix type, not a generic budget helper in isolation:
two scalar reads in order, followed by exactly 0x800 uninterpreted bytes,
including charge/cursor/error precedence and byte ownership.

The whole record FDE is `0x5968840..0x5968980` (320 bytes); its complete
fixed-copy helper is `0x58214b0..0x582153d` (141 bytes). For scalar reuse the
packet also retains both entire field1-5 readers (`0x5821340..0x5821425`,
`0x5822710..0x582284c`), the corresponding base scalar readers
(`0x5821250..0x5821335`, `0x58225c0..0x58226fc`), and the shared error
constructor `0x5822700..0x582270e`. The explicit static denominator is
**seven FDEs / 1,565 bytes / 455 instructions**; these contexts do not claim
new compiled-byte coverage. GNU2.45 / LLVM23.1.4 / Capstone5.0.7 complete
partitions agree, and GNU readelf independently confirms all FDE extents.

## Observations and byte/layout closure

The wrapper preserves its entry reader pointer in R14. Its first and second
calls at `0x5968872` and `0x596888a` use that same state and require raw success
byte0x12. Their scalar values are saved in R12 and R13, in that order. On a
scalar error, the wrapper forwards active error bytes into its result and
writes outer raw QWORD tag1. These are raw storage observations, not inferred
Rust enum variant names.

At `0x59688a2`, the same state reaches the complete 2048-byte helper. On helper
success, input bytes have been copied into helper-result+1. The wrapper's
success arm (`0x5968910..0x596897b`) performs **four memcpy operations of
exactly 0x800 bytes** through staging buffers and finally output+8. It then
writes first scalar at output+0x808, second scalar at output+0x810, and outer
raw QWORD tag0. No byte permutation, endian conversion or semantic blob header
loads occur in this path. The 2048 bytes remain exactly as on the wire; their
application meaning is still unknown. An owned `[u8; 2048]` is therefore a
faithful logical value, without pretending the safe Rust struct is that native
output layout or reproducing the original stack-copy granularity.

Both helper and wrapper copy calls resolve to actual slot0x64df508. Its
R_X86_64_GLOB_DAT symbol7 is resolved through the actual `.dynsym` linked string
table to `memcpy`; native readelf confirms `memcpy@GLIBC_2.14` in
`copy-relocation.txt`. The implementation performs a real safe byte copy,
not a mock memcpy and not an execution of original libc code.

## Charges, failures and prefix state

Each scalar is logically charged8, regardless of its encoded width. The blob
helper compares the raw mode DWORD with1. In canonical limited mode it checks
charged <= u64::MAX-2048, computes charged+2048 and **stores the new count
before comparing with the limit** (`0x58214b8..0x58214d9`). Overflow does not
store; a nonoverflowing refused charge stays stored. Unlimited mode leaves
the count unchanged. Limit failure precedes any input-length failure.

Only after admission does `0x58214e2..0x5821504` require remaining>=2048.
Short input reports additional=2048-remaining and consumes no blob bytes.
Successful input advances cursor by2048 and decreases remaining before the
copy (`0x5821504..0x582151f`). Earlier scalar consumption is never rolled
back. Normal two-scalar/blob charge is2064, not encoded byte length. The API
uses `None`/`Some(limit)` for canonical mode0/mode1 only; arbitrary raw modes,
invalid pointers and aliased mutable native descriptors are outside scope.

## Real scalar dependency and static sibling proof

The base `src/node115-u64-reader-state` crate is an actual MIT dependency,
not a placeholder. `sibling_proof.py` compares the complete fast and slow
reader pairs instruction by instruction. `sibling-equivalence.json` retains
every differing operand and the explicitly justified normalization:
function-relative branch destinations, actual paired jump-table targets,
actual RELATIVE slow-reader/error-constructor call bindings, and raw invalid
error field1 immediates (base fast2 / slow3, selected family5). All other
operations and partition offsets must match.

This establishes that the real base reader can be reused with precisely one
error-metadata projection: `Invalid.expected_raw=5` for both paths. Short and
long input preserve their distinct marker-consumption rules; only little endian
is selected by the wrapper's actual `xor edx,edx` slow-call setup. Nonminimal
encodings remain accepted. No new scalar-primitive completion credit is sought,
and this static normalization is not registered machine-code equality.

## Independent expectations and qualification

`oracle.py` independently expresses scalar branch mathematics and the whole
2048-byte record, not an instruction interpreter. **10,714** observations were
frozen before the new Rust directory existed; existing dependency Rust predates
that freeze and is identified honestly. Fixture SHA-256:
`bd485a0bde25600231e55bd22e91122ed07ec2881b711a667aa99605fdc784c9`.
The frozen raw TSV is stored losslessly as `cases.tsv.gz.hex` (gzip mtime0,
hex wrapped). Packing occurred **after Rust qualification** and changes no
input, row, expected outcome or original freeze hash. The qualifier decompresses
and authenticates the original bytes before comparing to `oracle.render()`;
the original raw file remains in ignored `work/environment/next-ten/bulk-record/
pre-rust-original-cases.tsv`.

Cases cover canonical/nonminimal scalar widths, fast/slow invalid markers,
truncated markers/payloads, first/second/blob budget boundaries, exact 2047/2048
blob availability, count overflow at each read, all256 seeded blob patterns,
complete payload byte equality and trailing input.

Actual Rust1.95.0 debug and release builds each match every case, including
both scalar values, all2048 payload bytes, consumed position and charged count.
Eight separately compiled production mutants exit normally and mismatch:
wrong field1, wrong blob charge, rollback refused charge, reject equal limit,
consume short blob, reverse bytes, swap fields, and consume2047 on success.
The actual unmodified base dependency is used by every mutant; only temporary
manifest path spelling is redirected to that same source. Exact source hashes
and first mismatches are in `qualification.json`, with original logs/output
under ignored `work/environment/next-ten/bulk-record/qualification/`.

The static verifier freshly checks all context hashes, call bindings, jump
Tables and sibling proof. Nineteen actual instruction/table anchors and two
wrong-identity controls are rejected. These mechanical controls bind evidence;
they are not native differential executions.

```
python3 -B research/work-items/RE-005-bulk-record-decoder-115/verify.py
python3 -B research/work-items/RE-005-bulk-record-decoder-115/sibling_proof.py
python3 -B research/work-items/RE-005-bulk-record-decoder-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-bulk-record-decoder/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-bulk-record-decoder/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-bulk-record-decoder/Cargo.toml
```

Only independently authored Rust runs on the host. The Linux rlib is built but
not executed. Native Result/padding/panic ABI, source field names/units, blob
schema, owning container lifecycle and whole-node behavior remain unclosed.
No captured execution/emulation, networking, chain action, binary equivalence,
full-scope gate or byte-total change is claimed. Next trace the owning
container's use of the two scalar values and uninterpreted fixed bytes.

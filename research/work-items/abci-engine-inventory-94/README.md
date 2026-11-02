# RE-001 / abci: exact engine.rs Location and anchor qualification

This packet asks which relocated panic Location records name exactly
`l1/src/abci/engine.rs`, which instruction-boundary LEAs reference them, and
which local literal setups and direct entry edges can be qualified from node
#94 bytes. It is a bounded observation packet, not a source reconstruction.
See [RESULT.md](RESULT.md) for findings, negative results and non-claims.

- Target: `artifacts/node/94/hl-node`, Linux x86-64 ELF, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Component/task: `abci`, RE-001; no component gate requested.
- Repository base: `e80dc0f3ffa6d95a7284f7e4654a0dfb9d01b67d`.
- Reference: can1357 revision `999556f6e0a474b8312db96ec3149e1c44e97c23`,
  [lead file](../../../references/can1357-hl/l1/abci/engine.rs), hash in JSON.
  Unlicensed search hints only. Absent reference text is represented by line,
  length and hash; present text is independently read from the target.
- New implementation and documentation: MIT. Captured byte excerpts retain
  the artifact's provenance; no reference implementation is copied.

## Scope, ownership and existing work

Only new files under this packet and the requested
[collector](../../../tools/abci_engine_inventory.py) and
[tests](../../../tests/test_abci_engine_inventory.py) are added. The collector
reuses existing MIT Python ELF/FDE and instruction helpers without modifying
them. Imported evidence, submodules, catalogue and gates are unchanged.

The active blocker was exact-file attribution: the existing state collector
hardcodes `state.rs`, and its sequential decoder stops at engine addresses
`0x220aaa4` and `0x220aab0`. The new collector adds only the needed scope logic
and register-form `66 45 21 /r` and `66 0f 76 /r` boundary decoding. The completed
transcripts and truncation/reserved-form controls verify that this specific
blocked inventory can proceed. This is not a general disassembler project.

The state, startup and node inventory packets supplied the method. The
requested engine branch/PR template was unavailable in this checkout; it was
not used as evidence. Existing engine work is cross-referenced and its owner
hashes, FDE/CIE identities and extents are revalidated against this artifact:

- [Checkpoint retention](../RE-001-checkpoint-retention-94/README.md).
- [Archive prefix](../RE-001-archive-prefix-94/README.md).
- [Snapshot admission](../RE-001-snapshot-admission-94/README.md).

Their behavior claims remain in those packets. Overlap is explicit in
`prior_work`, including the archive helper outside the exact-file range set.
The [state inventory](../abci-state-inventory-94/README.md) is a methodological
sibling; this packet does not claim its component or its results.

## Reproduce

From the repository root, Python 3.10+ standard library only. Development
validation used CPython 3.13.5. No executable target, subprocess, native
disassembler, network, installation or environment-state capture is needed by
the new collector, tests or verifier. The artifact is read through one mapping;
transcripts cover only scoped FDEs. All evidence addresses are link-time ELF VAs
with file offsets; FDE ends are exclusive. No normalization masks are applied.

```sh
python3 tools/abci_engine_inventory.py --out research/work-items/abci-engine-inventory-94/
python3 -m unittest tests.test_abci_engine_inventory -v
python3 research/work-items/abci-engine-inventory-94/verify.py
make verify
make catalogue-check
make reproduce
```

The collector regenerates the JSON files only. `MANIFEST.sha256` covers the
whitelisted packet files, including the verifier and both reports. The verifier
compares regenerated JSON byte for byte and checks pinned coordinates, counts,
anchor membership, call edges and every generated report block. Modifying a
report number without changing the evidence fails verification. Producer hashes
bind the new collector and the existing MIT helpers; reference and prior-packet
hashes are also retained. No timestamp, local home, host or search path is saved.
The embedded compiler prefix is recorded as hex in `path_bytes` and `PREFIX`;
it is artifact evidence, not analyst runtime state.

## Method and completeness

The digest gate runs before parsing. The collector checks ELF64 little-endian
x86-64 identity and required allocated, file-backed sections. Every RELATIVE
relocation pointing at the exact compiler path must decode as an aligned
pointer/u64 length/u32 line/u32 column Location; malformed matching records
abort instead of disappearing from the census. Source-coordinate duplicates
remain distinct records. The full compiler-path bytes, length, relocation entry
and Location record are retained for each slot.

Executable-section RIP LEA byte searches generate candidates only. Acceptance
requires full, sequential decoding from the owning actual FDE start, with no
resynchronization after unsupported bytes. Every internal direct branch must
land on a decoded boundary. FDE/CIE records, unwind-table entries and full body
hashes are retained. This establishes a reproducible linear partition, not a
reachable CFG or a complete source-function census.

Literal binding requires a scoped, boundary-qualified LEA plus decoded adjacent
pointer/length fields, a bounded register setup, or a bounded counted fragment.
The local RDX/ECX pair form ends at the immediate assignment and does not claim
the subsequent branch or callee. Counted fragments traverse at most four
u8-counted ASCII chunks with explicit C0/zero delimiters; zero stops traversal.
A probe must fit inside one chunk. Token probes require exact pointer/length
binding, so `tar` inside another diagnostic and `periodic` inside a longer path
are not additional token anchors. Chunk length is distinct from probe length.

Local setup context stops at the first transfer, capped at eight instructions.
Foreign first-party Locations in that context prevent binding to engine.rs.
An accepted anchor without a local engine Location is explicitly marked as
FDE co-location only. Shared FDE paths are listed below; they do not grant any
claim over the other files. All unaccepted nearby candidates retain reasons.

Direct CALL/JMP rel32 targets are decoded from signed displacements and admitted
only at exact scoped or revalidated prior-named FDE entries. Other direct
transfers and all indirect calls have separate unresolved accounting. No
source function name, ABI, callee side effect or argument role follows from an
edge. The finite numeric probe records MOV operands but binds no semantic
constant role. Compiler-transformed arithmetic is not exhaustively analyzed.

## Derived inventory

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | --- |
| anchors_with_local_engine_location | 15 |
| call_edges | 4 |
| constants_bound | 0 |
| constants_unresolved | 5 |
| counted_fragment_anchors | 12 |
| decoded_instructions | 6032 |
| diagnostics_absent | 7 |
| diagnostics_bound | 18 |
| diagnostics_probed | 27 |
| diagnostics_unresolved | 2 |
| location_leas | 28 |
| locations | 20 |
| pointer_length_anchors | 24 |
| prior_owner_overlaps | 5 |
| scoped_fde_bytes | 30352 |
| scoped_fdes | 9 |
| shared_first_party_fdes | 6 |
| tail_edges | 0 |
| unique_line_column | 12 |
<!-- END GENERATED METRICS -->

The denominator is relocated exact-path records and their observed LEA sites.
FDE counts are unwind ranges, not recovered functions or module coverage.
`call_edges` counts call sites; shared targets do not create extra functions.
Anchor counts are probe/site bindings; only the explicit local subset has a
per-Location setup association. Test assertions recompute these quantities.

<!-- BEGIN GENERATED LOCATIONS -->
| Slot VA | Line:column | LEA sites | FDE owners |
| --- | --- | --- | --- |
| 0x569dbe8 | 368:25 | 0x220bc1c | 0x2209d40 |
| 0x569dc00 | 142:13 | 0x220b885 | 0x2209d40 |
| 0x569dc18 | 143:13 | 0x220b8b0 | 0x2209d40 |
| 0x569dc30 | 144:13 | 0x220b8ce | 0x2209d40 |
| 0x569dc48 | 147:17 | 0x220b8f3 | 0x2209d40 |
| 0x569dc60 | 141:13 | 0x220b89e | 0x2209d40 |
| 0x569dc88 | 259:41 | 0x220c112 | 0x220bed0 |
| 0x569dcb8 | 224:17 | 0x220b91e | 0x2209d40 |
| 0x56e8ae0 | 503:17 | 0x330863b | 0x33084a0 |
| 0x56f3b18 | 460:35 | 0x37e35a4 | 0x37e2960 |
| 0x571c860 | 368:25 | 0x42e5b37, 0x42e71d7 | 0x42e4600, 0x42e5d40 |
| 0x571c878 | 142:13 | 0x42e5863, 0x42e6ef3 | 0x42e4600, 0x42e5d40 |
| 0x571c890 | 143:13 | 0x42e588e, 0x42e6f1e | 0x42e4600, 0x42e5d40 |
| 0x571c8a8 | 144:13 | 0x42e58ac, 0x42e6f3c | 0x42e4600, 0x42e5d40 |
| 0x571c8c0 | 147:17 | 0x42e58d1, 0x42e6f61 | 0x42e4600, 0x42e5d40 |
| 0x571c8d8 | 141:13 | 0x42e587c, 0x42e6f0c | 0x42e4600, 0x42e5d40 |
| 0x571c900 | 259:41 | 0x42e760a, 0x42e7bba | 0x42e73d0, 0x42e7980 |
| 0x571c930 | 286:17 | 0x432f443 | 0x432f310 |
| 0x571c948 | 279:25 | 0x432f3cc | 0x432f310 |
| 0x571c960 | 224:17 | 0x42e4d66, 0x42e6430 | 0x42e4600, 0x42e5d40 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| FDE start | End exclusive | Bytes | Observed first-party Location paths |
| --- | --- | --- | --- |
| 0x2209d40 | 0x220becb | 8587 | l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x220bed0 | 0x220c477 | 1447 | base/src/hour.rs, base/src/time.rs, l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x33084a0 | 0x33086f3 | 595 | l1/src/abci/engine.rs |
| 0x37e2960 | 0x37e3a6b | 4363 | l1/src/abci/engine.rs |
| 0x42e4600 | 0x42e5d3b | 5947 | l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x42e5d40 | 0x42e73ce | 5774 | l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x42e73d0 | 0x42e797d | 1453 | base/src/hour.rs, base/src/time.rs, l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x42e7980 | 0x42e7f2d | 1453 | base/src/hour.rs, base/src/time.rs, l1/src/abci/engine.rs, l1/src/exchange/exchange.rs |
| 0x432f310 | 0x432f5ed | 733 | l1/src/abci/engine.rs |
<!-- END GENERATED FDES -->

## Implementation and remaining work

No Rust implementation, Cargo build scope, raw/normalized source comparison,
helper closure or whole-ELF result is produced. These remain unmeasured; all
full-scope acceptance gates remain false. Static corruption controls validate
the evidence reader, not runtime behavior. The next bounded question is the
callee and argument provenance at the corresponding direct calls, especially
where the low-address caller differs from the higher-address pair. That needs
separate evidence before assigning operation names or reconstructing source.

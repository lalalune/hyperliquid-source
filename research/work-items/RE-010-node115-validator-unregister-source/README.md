# Node 115 validator unregistration source

Bounded progress for [#3928](https://github.com/lalalune/hyperliquid-source/issues/3928),
whose scope includes validator removal. Prior [#2225](https://github.com/lalalune/hyperliquid-source/pull/2225)
mapped the subtype and selected static handoffs. This adds independently
authored Rust for its logical keyed-state contract, including the actual
downstream history/set/map operations. It does not complete the broad component
or the consensus QC path; acceptance gates remain false.

## Target and evidence

Original `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The packet retains 15 complete original FDEs, 16,351 bytes / 3,531 instructions,
2,168 checked facts and 29 corruption controls. The parent FDE also contains
other subtypes; retaining it does not claim their implementation.

The core is `0x3c3d480..0x3c3f412`. The selected subtype is the normalized
nonzero/non-one arm at `0x3c3d4bc..0x3c3d4ed`, entering `0x3c3d61d`.
Full helper FDEs bind keyed comparison, tree/deque removal, set insertion,
follow-up entry insertion and the local cleanup dispatcher. Imported `memcmp`
is checked as a full 20-byte key comparator. Cleanup of local status `0x95`
selects the direct-return arm `0x3d08faa` through the original relative table.
No omitted business result is supplied through a callback or boolean.

`verify.py` authenticates the full target digest, FDEs, retained instructions,
helper targets, import and cleanup data. Controls deliberately bypass outer
digest/window checks and must fail the semantic fact checks. Static evidence
and independent model tests do not establish native runtime equivalence.

## Selected logical behavior

1. Look up the exact action key in state map `+0x110`. If the found value's
   raw word at `+0x20` is nonzero, return `0x144`. This precedes the validator
   lookup. Other words do not gate this path; the record is unchanged.
2. Look up the same key in validator map `+0xd0`. Missing returns `0x95`
   without writes. Capture the found value's twenty bytes at `+0x3c`.
3. Remove the action key from map `+0x10` through `0x3ce5780`. Remove the
   validator entry through `0x3712d20` or `0x4562050`. Remove the same key
   from map `+0x288` through `0x3903310` or `0x4562190`. Missing auxiliary
   entries do not prevent success.
4. Invoke `0x3c36ba0` with the action key and captured related key. Read the
   last key in the actual ordered collection at `+0x48`, or zero if empty.
   The native tree path follows the rightmost children; the deque path reads
   its final logical row. The owned projection preserves that iteration order
   and does not reinterpret it as a maximum operation.
5. Insert the related key into set `+0x180` if absent, then insert or replace
   map `+0x1e8` at that key with `(history_key, action_key)`. An existing set
   member does not suppress the map replacement. Return `0x1a2`.

The state uses real `BTreeMap`/`BTreeSet` collections. History is a sequence of
owned rows in native iteration order. Unobserved payloads are preserved in
unrelated entries and removed with the selected validator. Raw-word projections
and conservative offset-based names avoid assigning unsupported meanings to
the blocking field or the history/follow-up maps. This is not a parser for
native structs, pointers, padding or allocation records.

## Validation

Four tests compare status and complete owned state. A separate Python list
model generates 160 deterministic scenarios containing 4,000 sequential
actions: 845 accepted, 887 blocked and 2,268 missing-validator results. Every
action compares all seven collections, including untouched payloads and
blocking records. Fixture SHA-256:
`7c0a49a5ffad83052e3fec17f81513ac454fbcd3da8945a63a74cc24c8580464`.
Explicit cases cover blocked-before-missing precedence, mutation-free errors,
same related key replacing prior follow-up, empty history, last-row rather than
maximum selection, auxiliary removals and keys differing only in their tail.
Arbitrary history orders stress the selected row-reading operation; they are
not evidence that every such order is produced by native collection writers.

```sh
python3 src/node115-validator-unregister/tests/reference.py
cargo test --offline --locked --manifest-path src/node115-validator-unregister/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-validator-unregister/Cargo.toml
cargo fmt --check --manifest-path src/node115-validator-unregister/Cargo.toml
cargo clippy --offline --locked --all-targets --manifest-path src/node115-validator-unregister/Cargo.toml -- -D warnings
python3 research/work-items/RE-010-node115-validator-unregister-source/verify.py
make doctor verify catalogue-check reproduce
```

The verifier rejects all 29 altered facts, including subtype/gate/status,
key width, captured related-key offsets, removal targets, history source and
empty default, and follow-up writes. Only inspected safe repository tests are
run: the unfiltered suite includes captured-instruction emulation. No captured
binary was executed or emulated, and no live exchange operations were made.

## Overlap and limits

Current source, all 782 open PR titles/changed paths at selection, targeted
all-state semantic/address searches and relevant historical work distinguish
this source from #2225's static packet. Node94
[#1248](https://github.com/lalalune/hyperliquid-source/pull/1248) and
[#1062](https://github.com/lalalune/hyperliquid-source/pull/1062) are separate
targets. These checks do not individually inspect every closed historical diff.

Premises are valid logical collections, history in native iteration order,
successful allocation and normally returning generic diagnostics. The selected
local cleanup is proved to have no business effect. Physical map balancing,
conversion and hashing, pointer/result ABI, allocation failures/unwind,
registration and update subtypes, parent-to-state construction, outer action
decoding/authorization, live state and full consensus behavior are excluded.

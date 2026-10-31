# evm-kvs-inventory-94: bounded node-side EVM KVS evidence

Task: RE-009 / RE-001. Component: storage. Question: which decoded code
ranges reference panic Locations for exactly `node/src/evm_kvs.rs`, and what
length-bearing literals, numeric fields and direct calls are co-located?

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
[provenance](../../../provenance/artifacts.json) is the identity authority.
Checkout base: `1f8c67c63ca4794c9689235471c60297f8a5c985`; pinned reference
revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed,
inferred reference checkout is absent here. The existing literal catalogue
was consulted as a source of search hints, not authority; no reference source
or code is copied. Seed catalogue and RE-009 storage records were inspected.
Results below are tied to this target alone and do not establish source ownership.

## Reproduce

From the repository root, Python 3.10+ standard library; checked on Linux
x86-64 with Python 3.13.5:

```sh
python3 tools/evm_kvs_inventory.py --out research/work-items/evm-kvs-inventory-94/
python3 -m unittest tests.test_evm_kvs_inventory -v
python3 research/work-items/evm-kvs-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

No captured executable, external disassembler, network or installation is
used by this packet. A read-only memory mapping authenticates the input
before parsing. `inventory.json` and `instructions.json` regenerate byte for
byte; producer and helper hashes are recorded. `verify.py` checks a strict
file whitelist, manifest, target facts, regeneration and both report tables.
The manifest detects accidental drift; it is not a signature.

## Evidence and method

`inventory.json` retains raw Location, RELA, FDE, CIE, unwind index,
LEA, literal and transfer bytes with ELF link-time virtual addresses and file
offsets. End addresses are exclusive. `instructions.json` is a complete
linear boundary transcript for the scoped FDE extents, not a disassembly or
CFG. The actual FDE extents, rather than adjacent unwind starts, supply bounds.
The complete indexed FDE set is checked for ambiguous extents. Executable-section
LEA byte patterns propose candidates; candidates must be instruction-aligned
under the restricted, fail-closed decoder from FDE start and independently
decode to the exact slot. Internal direct branches must land on boundaries.
There is no reachability proof and an FDE can contain inlined or shared code.

The Location layout is a relocated pointer, u64 path length, u32 line and
u32 column. The exact path is matched in the authenticated ELF; raw target
path bytes are recorded as hex. A matching path relocation with malformed
record fails. Other Location layouts or path references without such a
relocation are outside this census. The LEA scan covers executable file-backed
sections; indirect references and non-LEA references are outside its scope.

Literal probes search exact bytes over the entire file. A binding requires a
scoped decoded RIP LEA plus either a matched pointer and length construction
or a bounded counted-ASCII chunk pattern with length and separator bytes.
The latter is containment evidence, not a formatter grammar. Rejected nearby
candidates and present-but-unbound/absent probes are retained. Immediate
numeric fields bind only through a unique adjacent pointer/length construction;
no meaning or unit is inferred. Calls/jumps are signed rel32 decoded and must
land exactly at a scoped FDE start. Out-of-scope and indirect transfers are not
resolved. No normalization is applied.

## Derived metrics

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 2 |
| counted_fragment_anchors | 22 |
| decoded_instructions | 18036 |
| diagnostics_absent | 1 |
| diagnostics_bound | 11 |
| diagnostics_probed | 14 |
| diagnostics_unresolved | 2 |
| location_leas | 38 |
| locations | 24 |
| out_of_scope_rel32_transfers | 1461 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 105955 |
| scoped_fdes | 7 |
| scoped_rel32_calls | 2 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 9 |
<!-- END GENERATED METRICS -->

See [RESULT.md](RESULT.md) for observations, caveats and non-claims. No gate
is requested. Independent Rust build/comparison and target runtime tests are
not available. Next investigate indirect calls and control-flow reachability
within a smaller anchored path, before attributing any behavior.

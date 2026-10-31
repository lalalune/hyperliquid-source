# nv-stream-inventory-94: exact-path Locations and bounded literal/call evidence

Task: RE-012 with RE-001 FDE grounding. Component: `node-runtime`.
Question: which node #94 unwind ranges contain decoded RIP-relative LEAs to
panic Locations for exactly `node/src/nv_stream.rs`, and which length-bearing
literals, adjacent numeric fields and direct call edges can those ranges support?

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The authority is [provenance/artifacts.json](../../../provenance/artifacts.json).
The embedded compiler prefix is matched as bytes; it is target provenance,
not the analyst's home directory. No analyst paths or environment are recorded.

Source checkout: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Reference lead revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
The can1357 tree is unlicensed inferred reference material. Its labels,
numeric values and phrases were search hints only. No Rust implementation,
comments or tests were copied, and generation never reads that tree.
The existing MIT ELF/FDE methodology was inspected in the open
spot-clearinghouse packet (PR #246) and in the
[InfoRequest packet](../RE-012-info-request-path/README.md).

## Scope and status

The census covers exact-path RELATIVE-relocated Location records in
`.data.rel.ro`, not the other paths in the node-runtime catalogue. An owning
FDE means an unwind range containing the LEA, not exclusive source ownership
or a recovered source function boundary. Shared/inlined code remains shared.
The comment seeds in [seed-candidates.json](../../catalogue/seed-candidates.json)
were inspected before instruction analysis; they did not determine the scope.

The related [RE-009 hashers inventory](../RE-009-storage-state-roots/hashers.json)
already includes functions whose `first_party_files` contain this path. This
packet neither re-derives its hashes nor assigns new hashing semantics.
No claim covers gossip_config, gossip_rpc, connections, hl_node startup/CLI,
consensus, node #115 or visor. No progress record or gate changes.

## Reproduce

From the repository root, with the authenticated target present, Python 3.10+
standard library only (validated here with Python 3.13.5 on Linux x86-64):

```sh
python3 tools/nv_stream_inventory.py --out research/work-items/nv-stream-inventory-94/
python3 -m unittest tests.test_nv_stream_inventory -v
python3 research/work-items/nv-stream-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

No external disassembler, native provider, installation or network is needed.
No captured executable runs. The tool uses a read-only file mapping, walks
RELA/CIE/FDE records, and decodes only the scoped code ranges. Regeneration
writes the JSON files only. The verifier checks the exact file whitelist and
manifest before authenticating the target and regenerating both JSON files in
memory. It also checks pinned Location tuples/call bytes and report metrics.
Tool/helper source hashes are embedded in `inventory.json`; `MANIFEST.sha256`
covers every packet file except itself, including `verify.py` and `RESULT.md`.
The manifest detects accidental drift; it is not an independent signature.

## Evidence and method

Addresses are ELF link-time VAs, with explicit file offsets and end-exclusive
FDE extents. No ASLR or analysis-provider rebase is applied. The packet contains:

- `inventory.json`: target identity, exact Location bytes and line/column,
  RELA bytes/addends, owning FDEs, LEAs, raw CIE/FDE/index records, literal
  occurrences, accepted/rejected bindings, constants, edges and explicit gaps.
- `instructions.json`: every scoped instruction as FDE-relative offset, raw
  bytes and a limited decoded kind. This is a boundary transcript, not lifted
  code. Full code digests accompany the FDE records.
- `RESULT.md`: bounded observations, inferences, negative results and verdict.

Each Location is the observed layout of a relocated pointer, u64 byte length,
u32 line and u32 column. The length must select exactly the embedded path,
and a matching path relocation with malformed layout fails the census.
Actual `.eh_frame` extents and their CIE/index relationships are checked,
including duplicate, overlapping, missing, zero-length and crossing ranges.
The unwind table's next-start value is never substituted for the FDE end.

RIP LEA byte scanning proposes candidates only. A restricted legacy x86-64
length decoder consumes prefixes, opcodes, ModRM, SIB, displacement and
immediate fields continuously from each scoped FDE start. Unknown encodings,
truncation and internal direct branches into operands fail closed; no fallback
or resynchronization exists. A proposed LEA must coincide with a decoded
instruction and pass a separate exact REX.W/RIP LEA decoder. Direct E8/E9
transfers likewise require a complete instruction and signed rel32 arithmetic;
accepted edges land exactly on a scoped FDE start. This is linear decoding
with internal branch alignment, not CFG reachability or dynamic execution.

A literal probe is `bound` only with a scoped decoded LEA and explicit length
evidence: adjacent pointer/qword-length stores; a supported register
pointer/immediate-length setup followed by a call; or bounded ASCII chunks
whose u8 lengths and C0 separators are checked from the LEA target through
the probe's containing chunk. A leading C0 is retained as a byte pattern.
Zero-length terminators stop traversal. The chunk method proves bytes and
containment, not a formatter grammar, placeholder values or a runtime log.
Rejected neighboring-string candidates remain visible in the JSON.

Searches cover exact probe bytes throughout the whole authenticated file.
`present-but-unbound` means bytes exist but the scoped binding rule failed;
`absent` means the exact bytes did not occur. Neither means missing runtime
functionality. The finite probe set is not every diagnostic in the component.

Constants are numeric co-locations only. Binding requires an immediate qword
store directly after a bound pointer/length record, at the next adjacent
field, uniquely for that label. Other immediate MOV occurrences remain
ambiguity controls. Comparisons, arithmetic immediates and propagated values
are not exhaustively enumerated. Names, units, capacities and timeouts remain
unresolved, including for bound numeric fields.

## Derived metrics

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 2 |
| constants_unresolved | 7 |
| counted_fragment_anchors | 15 |
| decoded_instructions | 12350 |
| diagnostics_absent | 4 |
| diagnostics_bound | 15 |
| diagnostics_probed | 24 |
| diagnostics_unresolved | 5 |
| location_leas | 40 |
| locations | 28 |
| out_of_scope_rel32_transfers | 940 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 70375 |
| scoped_fdes | 10 |
| scoped_rel32_calls | 6 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 16 |
<!-- END GENERATED METRICS -->

The table is generated from JSON metrics and checked against regeneration in
both this file and RESULT.md. Location slots and distinct line/column pairs
have separate denominators. LEA sites are not source functions. FDE byte
counts are not matched-window coverage or an engineering completion estimate.

## Implementation, comparison and controls

Independent Rust: not implemented. Build flags/lockfile, two-build result,
behavioral comparison and whole-ELF identity: not measured. No normalization
masks, artificial byte transplantation, helper closure or equivalence claim.

Tests exercise authenticated target facts and direct structural corruption:
wrong digest, Location pointer/length/line/column/path, relocation symbol and
addend, duplicate relocation slots, missing sections, executable flags, FDE
range and unwind pointer, shifted/embedded LEAs, rel32 displacement and landing,
ModRM/SIB and prefix boundaries, wrong/clobbered pointer/length registers,
nonadjacent fields, corrupted literals/counts/markers, cross-template traversal,
ambiguous numeric fields, manifest omission/duplication/traversal/extra files,
symlinks, JSON tampering and stale report counts. Structural controls call the
parsers directly on copy-on-write mappings; the public generator has no digest
bypass. Builds are tested with process spawning and networking forbidden.

The next question is to follow the direct edge from `0x439baf0` through
`0x435fca0` with a bounded CFG and argument/return analysis. That would test
whether the nearby verified diagnostic reflects a particular error branch;
this packet does not yet establish that behavior.

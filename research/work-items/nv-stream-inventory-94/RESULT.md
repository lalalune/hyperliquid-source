# Result: strong bounded static evidence, no recovered behavior

Target: node #94, `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Task: `nv-stream-inventory-94` (RE-012 / RE-001), exact path
`node/src/nv_stream.rs` only. No completion gate is requested.

## Observations

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

The Location census preserves every slot separately, including repeated
line/column pairs. Each slot has a RELATIVE relocation and instruction-boundary
checked RIP LEAs. Raw FDE/CIE/index records and complete linear instruction
transcripts make the attribution reviewable without an external disassembler.

The literal bindings include channel labels in FDE `0x227a0e0`,
`node_bootstrap` adjacent-field constructions in `0x439baf0`, `0x4759970` and
`0x4b3c880`, and `nv_stream_msg` / `gossip stream msg` constructions in
`0x4b3b930`. These are labels in bytes; they do not name recovered functions.

The counted-fragment evidence includes the batch-verification phrase in
`0x4360000`; old-client-block and reconnect-error phrases in the larger
forwarding-associated ranges; and bootstrap/local-state fragments. A probe
can be a substring of a longer length-bearing chunk. The JSON retains that
whole chunk, exact byte count, marker and offset; it does not assign the
probe's shorter length to the whole chunk. The `starting bootstrap` anchor
is `0x438924b` in FDE `0x4389070`, not a neighboring template reached by
scanning past a terminator from another LEA.

Direct rel32 call bytes establish edges from `0x439baf0`, `0x4759970` and
`0x4b3c880` into `0x435fca0` and `0x4389070`. For example,
`0x439c9b2: e8e932fcff` lands at `0x435fca0`, and
`0x439d2e9: e882bdfeff` lands at `0x4389070`.
All retained edges, signed displacements and next-instruction addresses are
in `inventory.json`. Out-of-scope direct transfers are counted separately;
none is silently assigned a source label or credited as helper closure.

The value 5000 is encoded immediately after the client-block/tx and execution
state label pointer/length fields, at `0x227ac52` and `0x227acf3`.
The value 8000000 follows the `gossip stream msg` label pair at `0x4b3bb2e`.
These are unique constructions per label under the stated rule. Calling them
channel capacities or read budgets would require additional dataflow/callee
analysis. Other numeric probes stay unresolved.

## Negative results and inferences

Present but unbound: `nv_stream_apply_execution_state`,
`nv_stream_forward_client_blocks`, `Too many unconfirmed blocks`,
`too many blocks to request`, and
`bootstrap ended past original block, is peer malicious?`.
In particular, the direct LEA for `too many blocks to request` is followed by
an ESI immediate of `0x35`, which differs from that probe's byte length.
The rejected candidate and following instructions are retained. A nearby
string or a pointer into a concatenated pool is insufficient for binding.

Exact byte probes absent from the file: `got client blocks`,
`no client blocks returned`, `nv stream execution state unavailable`, and
`client block parent round mismatch`. These are honest reference-lead
mismatches, not claims that an operation is absent from the program.

Descriptions such as “forwarding-associated” are tentative readings of
co-located diagnostics and reference leads. No source-level identity, protocol
transition, priority rule, buffering policy, time unit, state layout beyond
the recorded constructions, or side effect is established.

## Validation

Passed: the requested generator command; the packet unittest suite;
`verify.py` (manifest, pinned facts, byte-identical regeneration and report
counts); `make doctor`; `make verify test catalogue-check`; and `make reproduce`.
The clone's artifact/signature/import checks passed without an upstream key
workaround. Repository-wide tests and inventory/literal reproduction also
passed. No hosted CI, container run or target execution was attempted.

The report tables and all JSON outputs are checked against regeneration.
No GNU/LLVM objdump availability or command-line option affects these tests.
The target remained static throughout; no network, installation, captured
execution, GitHub action or progress/catalogue mutation was performed.

## Explicit non-claims and remaining gaps

- No runtime behavior, protocol semantics, source reconstruction, Rust build,
  binary equivalence, source coverage or whole-node completion claim.
- No exclusive FDE ownership or proof of CFG reachability; unwind ranges may
  contain shared/inlined code, and other code may lack unwind metadata.
- No claim for gossip_config.rs, gossip_rpc*.rs, connections.rs, hl_node.rs
  startup/CLI, consensus, node #115 or visor.
- No re-derivation or contradiction of
  [RE-009 hashing evidence](../RE-009-storage-state-roots/hashers.json).
- No indirect-call, vtable/data or helper closure. Only Location relocations
  are resolved here; no relocation-equivalence comparison is performed.
- No inferred formatter semantics or parameter values from counted chunks.
  No semantic constant names, units, capacities or timeout meanings.
- No matched-function denominator, raw/normalized identity result or accepted
  gate. All code/data and whole-ELF comparison work remains open.

Verdict: **strong for the bounded inventory question**. Length-bearing anchors,
actual FDE extents, decoded call edges, preserved negative results and
corruption controls provide substantially more than a Location dump. The
slice remains an evidence packet, not a recovered nv_stream implementation.
The next step is a narrowly selected CFG/argument study of a retained call
edge; expanding component scope is not required for that question.

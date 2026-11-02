# Result: node #94 engine.rs bounded static inventory

Verdict: **strong for this bounded static evidence claim**, with substantial
prior-work overlap. The useful addition is a complete exact-file census tied
to decoded boundaries, local diagnostic/Location setups, length-bearing literal
anchors, direct entry edges and explicit rejection records. FDE co-location
alone is weaker evidence and is labeled accordingly throughout. This packet
claims no runtime behavior, protocol semantics or source reconstruction.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The compiler prefix and exact `l1/src/abci/engine.rs` suffix are confirmed from
each relocation target's length-delimited bytes in `path_bytes`; the prefix is
hex-encoded in the collector. No local machine path is retained.

## Derived counts

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

These are inventory counts, not engineering completion or reconstructed bytes.
The [README](README.md) contains the full per-slot coordinates and FDE table.
The entire scoped linear instruction transcript is retained in
[instructions.json](instructions.json), with raw bytes and offsets. The
[inventory](inventory.json) distinguishes observations, unresolved candidates,
prior-work identity checks and inference limits.

## Diagnostics and literal anchors

<!-- BEGIN GENERATED DIAGNOSTICS -->
| Probe | Target bytes or hash-only identifier | Status | Occurrences | Anchors |
| --- | --- | --- | --- | --- |
| reference-line-33 | MARKED_FOR_DELETION | bound | 1 | 1 |
| reference-line-34 | freeze | bound | 35 | 3 |
| reference-line-35 | periodic | bound | 16 | 3 |
| reference-line-110 | reference-line-110 (hash only) | absent | 0 | 0 |
| reference-line-111 | assertion failed: !self.state.is_frozen() | bound | 2 | 3 |
| reference-line-405 | reference-line-405 (hash only) | absent | 0 | 0 |
| reference-line-495 | assertion failed: round > parent_round | bound | 2 | 3 |
| reference-line-496 | reference-line-496 (hash only) | absent | 0 | 0 |
| reference-line-497 | reference-line-497 (hash only) | absent | 0 | 0 |
| reference-line-498 | reference-line-498 (hash only) | absent | 0 | 0 |
| reference-line-499 | reference-line-499 (hash only) | absent | 0 | 0 |
| reference-line-509 | reference-line-509 (hash only) | absent | 0 | 0 |
| binary-1 | assertion failed: features_ok | bound | 2 | 3 |
| binary-2 | assertion failed: freeze_height >= self.locus.context.height() | present-but-unbound | 5 | 0 |
| binary-3 | /tmp/evm_db_bad_app_hash | bound | 2 | 3 |
| binary-4 | /tmp/abci_state_bad_app_hash.rmp | bound | 1 | 3 |
| binary-5 | computed app hash at height= | bound | 1 | 3 |
| binary-6 | new app hashes reached quorum: | bound | 1 | 3 |
| binary-7 | applied block | bound | 1 | 1 |
| binary-8 | straggler evm state checkpoint | bound | 1 | 1 |
| binary-9 | periodic_abci_state_status_base_dir does not exist: | bound | 1 | 1 |
| binary-10 | tar_evm_checkpoints failed: | bound | 1 | 1 |
| binary-11 | prune_lowest_evm_checkpoints failed: | bound | 1 | 1 |
| binary-12 | tar | bound | 257 | 1 |
| binary-13 | -C | bound | 158 | 1 |
| binary-14 | -cf | bound | 1 | 1 |
| binary-15 | abci_engine | present-but-unbound | 5 | 0 |
<!-- END GENERATED DIAGNOSTICS -->

The strongest local attribution links the round, frozen-state and features
assertions to engine Location setups; the counted computed-hash fragment also
shares its setup with an engine Location. The paired temporary-path literals
have decoded pointer and length stores in the same scoped ranges, but the
packet does not infer writes to those paths or a filesystem API.

The freeze-height assertion is deliberately **present-but-unbound**: its local
setup names `l1/src/exchange/exchange.rs`. Sharing an engine-scoped FDE does not
turn it into engine-file evidence. The `abci_engine` bytes occur beside the tar
literals but have no qualifying scoped LEA/length pair. Mere string-pool
adjacency is not binding. Both negative results are retained with raw contexts.

The reference-only absent candidates are stored only as line identifiers,
lengths and hashes. Exact bytes are absent from this capture; this does not
prove corresponding behavior is absent. In particular, the reference's phase
assertion wording cannot be validated from these bytes: the locally anchored
binary assertion is the features check. The cleanup-name lead at the final
seed is also unvalidated; its local target diagnostics name tar/prune failures.
No reference function name or proposed field meaning is adopted.

<!-- BEGIN GENERATED ANCHORS -->
| Probe | FDE | LEA | Literal target | Length | Proof | Local engine Location |
| --- | --- | --- | --- | --- | --- | --- |
| reference-line-33 | 0x33084a0 | 0x3308584 | 0x1fe44a | 20 | counted_ascii_chunks | none; range only |
| reference-line-34 | 0x220bed0 | 0x220bf56 | 0x3d74da | 6 | local_register_pointer_length | none; range only |
| reference-line-34 | 0x42e73d0 | 0x42e7456 | 0x6f0521 | 6 | local_register_pointer_length | none; range only |
| reference-line-34 | 0x42e7980 | 0x42e7a06 | 0x6f0521 | 6 | local_register_pointer_length | none; range only |
| reference-line-35 | 0x220bed0 | 0x220bf6c | 0x20a3e0 | 8 | register_pointer_length_pair | none; range only |
| reference-line-35 | 0x42e73d0 | 0x42e7464 | 0x20a3e0 | 8 | register_pointer_length_pair | none; range only |
| reference-line-35 | 0x42e7980 | 0x42e7a14 | 0x20a3e0 | 8 | register_pointer_length_pair | none; range only |
| reference-line-111 | 0x2209d40 | 0x220b897 | 0x3d74b1 | 41 | register_pointer_length_pair | 0x569dc60 |
| reference-line-111 | 0x42e4600 | 0x42e5875 | 0x6f04f8 | 41 | register_pointer_length_pair | 0x571c8d8 |
| reference-line-111 | 0x42e5d40 | 0x42e6f05 | 0x6f04f8 | 41 | register_pointer_length_pair | 0x571c8d8 |
| reference-line-495 | 0x2209d40 | 0x220b87e | 0x3d746e | 38 | register_pointer_length_pair | 0x569dc00 |
| reference-line-495 | 0x42e4600 | 0x42e585c | 0x6f04b5 | 38 | register_pointer_length_pair | 0x571c878 |
| reference-line-495 | 0x42e5d40 | 0x42e6eec | 0x6f04b5 | 38 | register_pointer_length_pair | 0x571c878 |
| binary-1 | 0x2209d40 | 0x220b8ec | 0x3d7494 | 29 | register_pointer_length_pair | 0x569dc48 |
| binary-1 | 0x42e4600 | 0x42e58ca | 0x6f04db | 29 | register_pointer_length_pair | 0x571c8c0 |
| binary-1 | 0x42e5d40 | 0x42e6f5a | 0x6f04db | 29 | register_pointer_length_pair | 0x571c8c0 |
| binary-3 | 0x2209d40 | 0x220bb27 | 0x3d7456 | 24 | adjacent_pointer_length_fields | none; range only |
| binary-3 | 0x42e4600 | 0x42e5a41 | 0x6f049d | 24 | adjacent_pointer_length_fields | none; range only |
| binary-3 | 0x42e5d40 | 0x42e70e1 | 0x6f049d | 24 | adjacent_pointer_length_fields | none; range only |
| binary-4 | 0x2209d40 | 0x220bb58 | 0x20c8e0 | 32 | adjacent_pointer_length_fields | none; range only |
| binary-4 | 0x42e4600 | 0x42e5a73 | 0x20c8e0 | 32 | adjacent_pointer_length_fields | none; range only |
| binary-4 | 0x42e5d40 | 0x42e7113 | 0x20c8e0 | 32 | adjacent_pointer_length_fields | none; range only |
| binary-5 | 0x2209d40 | 0x220bc15 | 0x1eaa6a | 28 | counted_ascii_chunks | 0x569dbe8 |
| binary-5 | 0x42e4600 | 0x42e5b30 | 0x1eaa6a | 28 | counted_ascii_chunks | 0x571c860 |
| binary-5 | 0x42e5d40 | 0x42e71d0 | 0x1eaa6a | 28 | counted_ascii_chunks | 0x571c860 |
| binary-6 | 0x2209d40 | 0x220ae9b | 0x1e2892 | 35 | counted_ascii_chunks | none; range only |
| binary-6 | 0x42e4600 | 0x42e4e77 | 0x1e2892 | 35 | counted_ascii_chunks | none; range only |
| binary-6 | 0x42e5d40 | 0x42e6541 | 0x1e2892 | 35 | counted_ascii_chunks | none; range only |
| binary-7 | 0x2209d40 | 0x220acb4 | 0x1e1550 | 18 | counted_ascii_chunks | none; range only |
| binary-8 | 0x33084a0 | 0x330862f | 0x1f42b5 | 51 | counted_ascii_chunks | 0x56e8ae0 |
| binary-9 | 0x37e2960 | 0x37e3723 | 0x1ffb27 | 52 | counted_ascii_chunks | none; range only |
| binary-10 | 0x432f310 | 0x432f3c5 | 0x1fd66f | 28 | counted_ascii_chunks | 0x571c948 |
| binary-11 | 0x432f310 | 0x432f43c | 0x1e78e4 | 37 | counted_ascii_chunks | 0x571c930 |
| binary-12 | 0x37e2960 | 0x37e310e | 0x59c095 | 3 | adjacent_pointer_length_fields | none; range only |
| binary-13 | 0x37e2960 | 0x37e3141 | 0x59c098 | 2 | adjacent_pointer_length_fields | none; range only |
| binary-14 | 0x37e2960 | 0x37e3174 | 0x59c09a | 3 | adjacent_pointer_length_fields | none; range only |
<!-- END GENERATED ANCHORS -->

Lengths on counted-fragment rows delimit the containing target chunk, not an
invented longer version of the probe. `local_register_pointer_length` proves
only the decoded pointer and immediate length before a branch. Other register
pairs retain the bounded setup through a CALL; adjacent-field pairs retain the
pointer store and qword length store. The `freeze`/`periodic`, marker and tar
observations overlap the existing packets cited below and are not new behavior
claims. Generic hour, time, runtime and allocator text is not added to pad the
candidate list.

## Direct edges and prior work

<!-- BEGIN GENERATED EDGES -->
| Caller | Call VA | Bytes | Signed rel32 | Exact entry | Endpoint scope |
| --- | --- | --- | --- | --- | --- |
| 0x2209d40 | 0x220b708 | e8c3070000 | 1987 | 0x220bed0 | scoped_entry |
| 0x37e2960 | 0x37e31cc | e8afac3c00 | 3976367 | 0x3bade80 | prior_named_entry |
| 0x42e4600 | 0x42e56bb | e8101d0000 | 7440 | 0x42e73d0 | scoped_entry |
| 0x42e5d40 | 0x42e6d7b | e8000c0000 | 3072 | 0x42e7980 | scoped_entry |
<!-- END GENERATED EDGES -->

The scoped call pairs connect corresponding low/high entry ranges already
suggested by reference seeds. Both endpoints independently reference exact-file
Locations; this does not recover their source names or explain the called
operation. The archive helper endpoint is already recorded in
[archive-prefix](../RE-001-archive-prefix-94/README.md), and its call site is
revalidated here without re-claiming that packet's prefix/tail semantics.

[Checkpoint retention](../RE-001-checkpoint-retention-94/README.md) and
[snapshot admission](../RE-001-snapshot-admission-94/README.md) already cover
the corresponding marker/height and snapshot-prefix slices. Every shared owner
is checked against the target body hash, actual FDE/CIE and extent. Their
original negative results and limitations are preserved. This inventory neither
supersedes those packets nor credits their findings as new reconstruction.

<!-- BEGIN GENERATED TRANSFERS -->
| Transfer disposition | Sites |
| --- | --- |
| call_indirect | 293 |
| external_unresolved_call_rel32 | 158 |
| internal_jmp_rel32 | 133 |
| prior_named_entry_call_rel32 | 1 |
| scoped_entry_call_rel32 | 3 |
<!-- END GENERATED TRANSFERS -->

Internal jumps are not external call edges. Direct calls outside the admitted
entries remain unresolved; indirect calls are counted without dereferencing
slots or assigning names. The retained transcripts permit inspection of those
gaps but do not close them.

## Numeric hints

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Numeric hint | Status | Decoded MOV occurrences (not bindings) |
| --- | --- | --- | --- |
| reference-line-28 | 390 | unresolved | 0 |
| reference-line-29 | 3 | unresolved | 3 |
| reference-line-30 | 2 | unresolved | 2 |
| reference-line-31 | 10000 | unresolved | 0 |
| reference-line-32 | 100 | unresolved | 1 |
<!-- END GENERATED CONSTANTS -->

No constant is bound merely because its numeric value appears in an FDE.
The retained MOV occurrences have decoded operands, but lack a unique link to
the suggested role; several occur in shared ranges. The probe is deliberately
limited to MOV immediates and does not establish absence of optimized arithmetic.
The existing snapshot arithmetic evidence remains in the snapshot packet.

## Validation and explicit non-claims

Passed: collector regeneration, the focused unittest suite, packet verifier,
`make doctor`, `make verify`, `make catalogue-check` and `make reproduce`.
The focused tests run the collector and verifier with subprocess and network
entry points forbidden. The exact regeneration and report-table controls pass.

The required broader `make test` was attempted with a temporary process audit
guard to enforce the requested static scope. It stopped during
[test_action_dispatch_drift.py](../../../tests/test_action_dispatch_drift.py)
before an unrelated objdump invocation. Earlier guard attempts stopped at
process-spawn/readelf setup before the guard was narrowed to allow those
read-only operations; none is a full-suite pass. The final attempt reached the
legacy disassembly check and was terminated. No legacy tests or tools were
modified, and no full repository-suite success is claimed. The new packet has
no objdump dependency. Broader legacy tests also include whole-text disassembly
in [test_bincode_varint_slow.py](../../../tests/test_bincode_varint_slow.py),
which is outside this task's scoped-disassembly constraint.

Corruption controls exercise the readers below the digest gate as well as the
normal fail-closed public entry point. They cover Location/relocation changes, missing
sections, FDE extents, shifted/embedded LEAs, relative-call target changes,
length-field and counted-fragment corruption, report drift and manifest attacks.

- No native execution/emulation, public networking, chain actions or signing.
- No original source, Rust reconstruction, layout/ABI recovery or protocol semantics.
- No source-function ownership or names, full CFG/reachability or full call graph.
- No claims for state.rs, other abci files, node, clearinghouse, exchange, or
  generic base/foundation helper internals. Foreign Location records explain
  attribution exclusions only.
- No filesystem effects, shell arguments, actual logs or formatter grammar.
- No inferred constant roles/units and no implicit validation of reference prose.
- No complete helper, indirect-call, relocation, vtable or data closure.
- No whole-ELF comparison, rebuild, matched-window denominator, full component
  gate, #115 comparison, visor claim, hosted CI or container-validation claim.

Next: qualify the direct-call argument provenance and callee behavior in a
separate bounded packet before independently reconstructing an operation.

# Result: node #94 tcp_stream exact-file evidence

**Verdict: strong for the bounded static inventory, not a source or behavior
reconstruction.** The exact-file census is complete under the authenticated
RELATIVE-Location representation. The smaller owners supply length-bearing
anchors and direct entry-call evidence; shared owners have explicit exclusions.
No matched-function denominator, module completion or progress gate is claimed.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Scope: exactly `net_utils/src/tcp/tcp_stream.rs`.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | --- |
| adjacent_location_calls | 34 |
| byte_proven_but_unattributed_setups | 12 |
| call_edges | 3 |
| constants_bound | 0 |
| constants_unresolved | 10 |
| counted_fragment_anchors | 0 |
| decoded_instructions | 12213 |
| diagnostics_absent | 12 |
| diagnostics_bound | 3 |
| diagnostics_probed | 18 |
| diagnostics_unresolved | 3 |
| location_leas | 34 |
| locations | 15 |
| only_exact_file_first_party_fdes | 6 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 67679 |
| scoped_fdes | 12 |
| shared_first_party_fdes | 6 |
| tail_edges | 0 |
| unique_line_column | 4 |
<!-- END GENERATED METRICS -->

## What the bytes establish

Location slots at line 45:80 lead to small owners `0x2034eb0` and `0x4387c80`;
line 50:73 also occurs in `0x20485e0` and `0x439edd0`. Line 33:60 occurs in
`0x20487f0`, `0x439efe0` and the shared `0x4b399a0`. Line 60:82 occurs in
`0x2036460` and `0x4387910`, which also reference `tcp/write.rs`. The complete
slot/site/owner table is generated in [README.md](README.md); these coordinates
are binary facts, not inferred source function names.

Every census LEA is a decoded `RDI` setup followed immediately by `FF 15 rel32`.
The referenced slots `0x576f038` and `0x576f040` have RELATIVE relocations to
`0x157b560` and `0x157b540`, respectively. JSON preserves raw instructions,
slot bytes and relocation records. These callee entries are checked against
actual FDEs; their internals and names are not claimed.

## Diagnostics and attribution

<!-- BEGIN GENERATED DIAGNOSTICS -->
| Probe | Target text / hash-only identifier | Status | Occurrences | Bound anchors |
| --- | --- | --- | --- | --- |
| reference-line-136 | reference-line-136 (hash only) | absent | 0 | 0 |
| reference-line-137 | reference-line-137 (hash only) | absent | 0 | 0 |
| reference-line-139 | reference-line-139 (hash only) | absent | 0 | 0 |
| reference-line-141 | reference-line-141 (hash only) | absent | 0 | 0 |
| reference-line-142 | reference-line-142 (hash only) | absent | 0 | 0 |
| reference-line-143 | reference-line-143 (hash only) | absent | 0 | 0 |
| reference-line-144 | reference-line-144 (hash only) | absent | 0 | 0 |
| reference-line-145 | reference-line-145 (hash only) | absent | 0 | 0 |
| reference-line-146 | reference-line-146 (hash only) | absent | 0 | 0 |
| reference-line-147 | reference-line-147 (hash only) | absent | 0 | 0 |
| reference-line-148 | reference-line-148 (hash only) | absent | 0 | 0 |
| reference-line-203 | tcp_stream_with_retry | present-but-unbound | 1 | 0 |
| reference-line-286 | tcp_bytes | present-but-unbound | 5 | 0 |
| reference-line-507 | reference-line-507 (hash only) | absent | 0 | 0 |
| binary-1 | early eof | bound | 1 | 4 |
| binary-2 | could not resolve to any address | bound | 2 | 2 |
| binary-3 | ip not v4 | bound | 5 | 2 |
| binary-4 | tcp_read_exact | present-but-unbound | 5 | 0 |
<!-- END GENERATED DIAGNOSTICS -->

<!-- BEGIN GENERATED ANCHORS -->
| Probe | Owner | LEA | Target | Length | Proof | Owner Location slots |
| --- | --- | --- | --- | --- | --- | --- |
| binary-1 | 0x2034eb0 | 0x2034fc8 | 0x7d0cd4 | 9 | register_pointer_length_pair | 0x5697298 |
| binary-1 | 0x20485e0 | 0x20486cf | 0x7d0cd4 | 9 | register_pointer_length_pair | 0x5697298, 0x56972b0 |
| binary-1 | 0x4387c80 | 0x4387d98 | 0x7d0cd4 | 9 | register_pointer_length_pair | 0x571ec08 |
| binary-1 | 0x439edd0 | 0x439eebf | 0x7d0cd4 | 9 | register_pointer_length_pair | 0x571ec08, 0x571ec20 |
| binary-2 | 0x20487f0 | 0x204892e | 0x20c140 | 32 | register_pointer_length_pair | 0x56972e0 |
| binary-2 | 0x439efe0 | 0x439f111 | 0x20c140 | 32 | register_pointer_length_pair | 0x571ec50 |
| binary-3 | 0x20487f0 | 0x2048c6c | 0x3c4be5 | 9 | register_pointer_length_pair | 0x56972e0 |
| binary-3 | 0x439efe0 | 0x439f586 | 0x6f1620 | 9 | register_pointer_length_pair | 0x571ec50 |
<!-- END GENERATED ANCHORS -->

The `early eof` anchors load RSI and then EDX=9, EDI=37 before the indirect call.
These are revalidations of existing frame-read evidence, not a novel error-code
interpretation. The `could not resolve to any address` anchors use RSI, EDX=32,
EDI=20 and the same call slot. The `ip not v4` anchors use RDI, ESI=9 before a
direct call. These operand sequences establish bounded text spans without
claiming the operation performed by either callee.

The immediately adjacent `tcp_bytes` text after `ip not v4` is excluded by the
length operand. Its own pointer/length setups, and the `tcp_read_exact` setups,
occur in shared owners and remain unbound here. The retry probe has a valid
counted-text anchor in `0x4b399a0`, but no exact-file Location in that local
setup; it also remains unbound. Rejected candidates, successful byte proofs without attribution, and reasons are retained,
including attempts to cross neighboring text. No counted-chunk anchor is
promoted merely because it shares a large FDE.

No admitted diagnostic has an individual panic-line binding in its local call
setup. Admission rests on length-bearing instructions in small FDEs whose
observed first-party Locations are exclusively this file. That is stronger than
shared-range proximity but still does not establish exclusive source ownership,
original names or a source-level relationship between the diagnostic and a
particular panic. The JSON lists the owner Location slots explicitly.

## Reference mismatches and prior evidence

The reference's frame-reader assignment for `0x20487f0` / `0x439efe0` is not
accepted. The exact-file Location in each is line 33:60, and the tightly bound
text concerns address resolution and IPv4. This conflicts with using those
seeds as established frame-decoding evidence. It does not by itself prove an
alternative function name. The large shared owners `0x4744160` and `0x4b72900`
are discovered through Locations despite their absence from this file's
catalogue seed set. Seed membership is never used as a boundary proof.

The reference's quoted display/error strings mostly have no exact byte match;
the generated diagnostic table records absence over the complete authenticated
file. Absence of literal syntax does not prove absence of equivalent runtime
formatting. Numeric hints likewise cannot establish policy, units or layout.

Existing findings are preserved and credited:

- [transport-tcp-frame-read-94](../transport-tcp-frame-read-94/README.md)
  already identifies the EOF pointer/length/EDI sequences and header readers.
  This packet redecodes every EOF site from an FDE entry, checks the prior extent,
  pointer/length, EDI operand and FF15 slot, and adds exact-file Location
  attribution. It does not re-claim header, framing, timeout, compression or
  chunk semantics. The prior packet explains why the EOF numeric operand is
  not a project-defined error code; no new interpretation is offered here.
- [RE-009-storage-state-roots](../RE-009-storage-state-roots/README.md)
  already attributes lines 45 and 50 of this file to shared owner `0x22615b0`.
  That extent and line set are revalidated. The broader storage literal in that
  owner is not a tcp_stream diagnostic claim.
- [gossip-rpc-client-inventory-94](../gossip-rpc-client-inventory-94/README.md),
  [gossip-config-inventory-94](../gossip-config-inventory-94/README.md) and
  [evm-kvs-inventory-94](../evm-kvs-inventory-94/README.md) already record shared
  owner ranges. Their intersecting body hashes, extents, FDE/CIE records and
  unwind-index records are revalidated. This does not transfer their diagnostic
  or semantic claims into this scope.

`prior_work` in [inventory.json](inventory.json) records the exact input hashes
and revalidation scope. Earlier negative results remain untouched. Neighboring
frame-write and LZ4 packets remain outside the claim; no decompressor, writer,
retry or listener semantics are imported.

## Entry edges and unresolved transfers

<!-- BEGIN GENERATED EDGES -->
| Caller | Call VA | Bytes | Signed rel32 | Callee entry | Callee Locations |
| --- | --- | --- | --- | --- | --- |
| 0x22615b0 | 0x2264b21 | e88a03ddff | -2292854 | 0x2034eb0 | 0x5697298 |
| 0x4744160 | 0x47450d2 | e8a92bc4ff | -3920983 | 0x4387c80 | 0x571ec08 |
| 0x4b72900 | 0x4b737f4 | e8874481ff | -8305529 | 0x4387c80 | 0x571ec08 |
<!-- END GENERATED EDGES -->

Each listed E8 displacement is sign-decoded as `site + 5 + displacement` and
lands exactly at a scoped FDE entry whose first-party Location observations are
only tcp_stream. The caller is shared; the callee identity is its address and
Location set, not an inferred name. The preceding operand context is retained.
No conditional reachability or call-argument semantics are inferred.

<!-- BEGIN GENERATED TRANSFERS -->
| Disposition | Sites |
| --- | --- |
| call_indirect | 724 |
| external_unresolved_call_rel32 | 408 |
| internal_jmp_rel32 | 596 |
| jmp_indirect | 71 |
| scoped_entry_call_rel32 | 3 |
<!-- END GENERATED TRANSFERS -->

Internal jumps are not inter-FDE edges. External direct transfers remain
unresolved, and indirect calls/branches are counted separately. The adjacent
Location call slots are byte-qualified above but do not enter the rel32 edge
count. No generic helper is added to enlarge the graph.

## Numeric hints

<!-- BEGIN GENERATED CONSTANTS -->
| Hint | Value | Status | Decoded MOV occurrences (not bindings) |
| --- | --- | --- | --- |
| reference-line-34 | 5 | unresolved | 10 |
| reference-line-35 | 0 | unresolved | 62 |
| reference-line-36 | 1 | unresolved | 91 |
| reference-line-37 | 40 | unresolved | 0 |
| reference-line-38 | 20 | unresolved | 3 |
| reference-line-39 | 60 | unresolved | 0 |
| reference-line-40 | 10 | unresolved | 6 |
| reference-line-41 | 2 | unresolved | 26 |
| reference-line-42 | 4000000 | unresolved | 3 |
| reference-line-43 | 37 | unresolved | 7 |
<!-- END GENERATED CONSTANTS -->

The decoded MOV occurrence list is a search result, not a semantic binding.
Even a matching value in an exact-file owner does not establish its role or
units. In particular, the EDI operand beside the EOF literal is retained as
prior byte evidence, while the reference's proposed project constant role
remains unaccepted. Floating immediates, optimized arithmetic and byte stores
are outside this restricted numeric probe, so lack of a MOV match is not
numeric absence.

## Validation and limitations

Passed: collector regeneration; the focused stdlib unittest suite; packet
whitelist/hash verification, node digest authentication, pinned facts,
byte-identical JSON regeneration and report-count checks; `make doctor`.
Collection and packet verification also pass with subprocess and network entry
points forbidden by the focused tests.

`make verify` authenticates the captured artifacts and signatures, then fails
because this clone lacks `upstream/node/pub_key.asc`. `make reproduce` stops at
the same prerequisite before its inventory/literal regeneration. Neither is
reported as a pass and no reference setup, install or network recovery was run.
`make catalogue-check` reports stale `research/catalogue/components.json`;
generated catalogues and progress gates are unchanged.

The broader `make test` attempt used a transient audit guard against subprocess
and network effects, while allowing its isolated unittest children. An initial
guard version stopped at child startup; the corrected attempt reached
`tests/test_abci_state_link.py` and rejected that legacy test's additional Python
process. This is a guard-limited run, not a full-suite pass or evidence that the
legacy implementation fails. No captured executable, network request or native
disassembler was launched. No hosted CI or container success is claimed.

- No captured node/visor execution, runtime behavior or protocol semantics
  beyond the recorded bytes; no networking, signing or chain actions.
- No recovered source, Rust component, compiler build, whole-ELF equivalence,
  function-coverage denominator, #115 comparison or visor result.
- No claims on `read.rs`, `write.rs`, `reconnecting_tcp_client.rs`,
  `tcp_listener.rs`, `lz4_stats.rs`, `traffic_recorder.rs`, node, l1 or generic
  base/foundation internals. Their Location names only expose shared ranges.
- No exclusive FDE ownership, names, complete CFG, indirect-branch reachability,
  callee semantics, helper closure, vtable/data closure or general relocation
  closure. Linear decoding is complete only over the scoped FDE extents.
- No literal padding: shared-range candidates remain unresolved, absent
  reference text is withheld, and prior observations receive no novelty credit.

Next bounded question: qualify the argument provenance and callee behavior of
the line-33 owners around their address-related anchors before assigning a
source-level operation. That would test the reference's seed mismatch more
deeply without expanding this packet's scope.

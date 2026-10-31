# Result: node #94 consensus RPC static evidence

**Verdict: strong for the bounded static inventory.** The useful depth is the
complete exact-path census, raw relocation/FDE evidence, complete scoped
instruction decoding, explicit pointer/length bindings, an internal scoped
call edge and retained negative reference checks. This remains a partial
research slice; it does not reconstruct consensus RPC.

All facts refer to `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are ELF link-time VAs and explicit file offsets. Actual FDE ends
are exclusive. The machine-readable sources are [inventory.json](inventory.json)
and [instructions.json](instructions.json).

## Derived results

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 2 |
| decoded_instructions | 4024 |
| diagnostics_absent | 0 |
| diagnostics_bound | 14 |
| diagnostics_probed | 22 |
| diagnostics_unresolved | 8 |
| indirect_calls_unresolved | 238 |
| indirect_jumps_unresolved | 21 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 208 |
| location_leas | 14 |
| locations | 9 |
| pointer_length_anchors | 14 |
| scoped_fde_bytes | 21907 |
| scoped_fdes | 4 |
| scoped_rel32_calls | 1 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 9 |
| unresolved_external_rel32_calls | 119 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

The Location slots are counted individually, with their exact path lengths,
line/column fields, RELA addends and decoded LEA sites. In particular, paired
LEAs at nearby panic sites remain separate instruction references to the same
Location. No exclusive source ownership follows from sharing an unwind range.

## Diagnostic and literal anchors

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| make_rpc_request_get_node_ip | bound | 28 | 1 | 1 |
| node_rpc_request | bound | 16 | 1 | 1 |
| BUG: unknown validator:  | present-but-unbound | 24 | 1 | 0 |
| client blocks first= | present-but-unbound | 20 | 1 | 0 |
| @@ finished bootstrap @@ [start_round:  | present-but-unbound | 39 | 1 | 0 |
| rpc_clone_main_validators | bound | 25 | 1 | 1 |
| Peer response | bound | 13 | 1 | 1 |
| Peer timed out | bound | 14 | 1 | 1 |
| rpc_task_get_peers | bound | 18 | 1 | 1 |
| Rpc task inbound | bound | 16 | 1 | 1 |
| Rpc task outbound | bound | 17 | 1 | 1 |
| Rpc task response | bound | 17 | 1 | 1 |
| Rpc task size stats | bound | 19 | 1 | 1 |
| hash_to_tx | bound | 10 | 1 | 1 |
| hash_to_block | bound | 13 | 2 | 1 |
| ask_peer | bound | 8 | 2 | 1 |
| Rpc task failed to send response | bound | 32 | 1 | 1 |
| Incoming tcp stream | present-but-unbound | 19 | 1 | 0 |
| Received rpc request | present-but-unbound | 20 | 1 | 0 |
| send consensus rpc resp | present-but-unbound | 23 | 1 | 0 |
| Failed to receive response from rpc task | present-but-unbound | 40 | 1 | 0 |
| /override_consensus_rpc_c_signers.json | present-but-unbound | 38 | 1 | 0 |
<!-- END GENERATED LITERALS -->

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE start | LEA VA | Literal VA | Length | Proof |
| --- | --- | --- | --- | --- | --- |
| make_rpc_request_get_node_ip | 0x43848f0 | 0x4384b27 | 0x6f1338 | 28 | register_pointer_length_pair |
| node_rpc_request | 0x43848f0 | 0x4384cf9 | 0x2036b0 | 16 | adjacent_pointer_length_fields |
| rpc_clone_main_validators | 0x4b33eb0 | 0x4b3435e | 0x706c97 | 25 | register_pointer_length_pair |
| Peer response | 0x4b33eb0 | 0x4b35b11 | 0x706cb0 | 13 | adjacent_pointer_length_fields |
| Peer timed out | 0x4b33eb0 | 0x4b3566a | 0x706cbd | 14 | adjacent_pointer_length_fields |
| rpc_task_get_peers | 0x4b33eb0 | 0x4b348da | 0x706ccb | 18 | register_pointer_length_pair |
| Rpc task inbound | 0x4b33eb0 | 0x4b34126 | 0x2043d0 | 16 | adjacent_pointer_length_fields |
| Rpc task outbound | 0x4b33eb0 | 0x4b33f58 | 0x706cdd | 17 | adjacent_pointer_length_fields |
| Rpc task response | 0x4b33eb0 | 0x4b35d42 | 0x706cee | 17 | adjacent_pointer_length_fields |
| Rpc task size stats | 0x47b3f50 | 0x47b42fd | 0x6fb955 | 19 | adjacent_pointer_length_fields |
| hash_to_tx | 0x47b3f50 | 0x47b4318 | 0x6fb93e | 10 | adjacent_pointer_length_fields |
| hash_to_block | 0x47b3f50 | 0x47b4340 | 0x6fb948 | 13 | adjacent_pointer_length_fields |
| ask_peer | 0x4b33eb0 | 0x4b3507f | 0x20a990 | 8 | adjacent_pointer_length_fields |
| Rpc task failed to send response | 0x4b33eb0 | 0x4b35f35 | 0x20c7c0 | 32 | adjacent_pointer_length_fields |
<!-- END GENERATED ANCHORS -->

`node_rpc_request` at `0x2036b0` is addressed by LEA `0x4384cf9` in FDE
`0x43848f0`. Its pointer is stored at `[rbx+0x150]`, followed by a qword
immediate length at `[rbx+0x158]` matching the exact target string length.
All setup bytes are retained; changing the length, pointer register or adjacent
field rejects the proof. The `make_rpc_request_get_node_ip` binding uses R8
and R9D through a contiguous call setup; the intervening R14-to-RCX move is
explicitly decoded and cannot be treated as harmless if it clobbers the pair.

`rpc_clone_main_validators` is especially local evidence: its pointer/length
setup at `0x4b3435e` also contains the RPC Location LEA at `0x4b34365`, naming
Location `0x5738698`. It ends in a decoded direct call at `0x4b34379`.
This associates bytes in the same call setup, without recovering the callee,
argument roles, a cloning operation or validation behavior.

The reference puts “Peer response” and “Peer timed out” near the outbound and
peer-update leads. In this packet their accepted pointer/length setups occur
in `0x4b33eb0`; neither binds in `0x47b05f0` or `0x47b3f50`.
The server-message probes exist in the binary but have no exact scoped LEA
binding here. Their presence in nearby pooled data does not attribute them to
RPC, and this packet makes no claim about server.rs.

The unknown-validator and override-path literals have scoped LEAs addressing
short preceding headers, retained in `nearby_unbound_leas`. They stay
present-but-unbound under the explicit pointer/length rule. The bootstrap and
client-block probes likewise do not bind under this rule. No absent candidate
is manufactured from the reference's ellipsis paraphrases; absence means
only an exact whole-file search miss, never absence of equivalent behavior.

## Direct call and reference checks

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x4b33eb0 | 0x4b35337 | e8b4f584ff | -8063564 | 0x43848f0 |
<!-- END GENERATED EDGES -->

The raw call satisfies `next_instruction + signed_displacement = callee`.
Both endpoints independently reference RPC Locations and are actual FDE
entries. This proves a static instruction edge; reachability, arguments,
effects and scheduling remain unknown.

Reference call leads from `0x47b05f0` to `0x4553eb0` at `0x47b0780`, and
from `0x47b3f50` to `0x4553910` at `0x47b40c6`, are also decoded E8 edges.
The destinations are FDE starts but do not reference the exact RPC Location
path. They are recorded as external, unresolved targets, excluded from the
scoped call-edge count and from component ownership. All other direct
transfers are preserved; indirect-call and jump counts do not imply closure.

## Constants

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| request timeout | unresolved | none |
| maximum blocks per response | unresolved | none |
<!-- END GENERATED CONSTANTS -->

The reference's configuration roles do not supply authenticated numeric values.
No immediate has a unique demonstrated relationship to either role. Decoded
length stores, timer/helper arithmetic and control fields cannot establish a
request timeout, unit or block limit. The unresolved entries deliberately do
not invent numeric candidates or promote co-location into semantics.

## Prior work, non-claims and remaining gaps

The overlap with [RE-008](../RE-008-consensus-wire-state/consensus-wire.json)
is its seed-boundary evidence, not its wire/state semantics. Its lack of
Location ownership under its own scope is consistent with this packet.
The local [RE-009 hashers packet](../RE-009-storage-state-roots/hashers.json)
does not contain the RPC co-location described in the task; the exact local
hash and empty intersection are recorded. Neither prior packet is modified.

- No runtime behavior, protocol semantics beyond recorded bytes, source
  reconstruction, recovered Rust, build or binary-equivalence claim.
- No CFG reachability, complete function census, source names, ABI recovery,
  exclusive FDE ownership, matched-window denominator or progress gate.
- No claims for other consensus files, server/state/network/mempool, slack_alert,
  spot_meta, spot_clearinghouse, evm_kvs, nv_stream, tokio, networking internals
  or generic base/foundation helpers.
- No helper closure, full call graph, indirect/vtable/data closure, full
  relocation comparison or whole-ELF result. Shared and inlined code, split
  bodies, and code lacking FDEs remain gaps.
- No #115 or visor parity, captured execution, chain action or network use.

## Validation and next question

Local checks passed: CLI regeneration; the focused unittest suite; packet
verification normally and under `python -O`; `make doctor`; `make verify`;
`make test`; `make catalogue-check`; and `make reproduce`. The possible
unrelated missing-public-key failure did not occur in this checkout. There
are no remaining validation failures. No hosted CI or container result is
claimed.

The repository-wide tests include pre-existing native-tool checks; those
are separate from this packet's Python-only producer, verifier and focused
tests. All retained artifact signatures, imported evidence and source pins
verified, and the legacy inventories/literal classifications reproduced.
The final report-link and local-state test was also checked in the focused
suite after the repository-wide run.

Corruption controls run both at the whole-artifact digest gate and beneath
that gate against small instruction fixtures or private copy-on-write maps.
They test altered Location/path/relocation fields, section/FDE corruption,
shifted or embedded opcode candidates, direct-edge operands, immediate lengths,
wrong pointer registers and field offsets, clobbered call setups, and stale
or tampered packet reports/manifests. Regeneration compares exact bytes;
it does not normalize any code or operand. The tests prohibit external
processes and network calls during packet generation and verification.

The next bounded question is to identify the header-prefixed literal format
used at `0x4384bc9` and `0x4b341e6` with target-grounded descriptor boundaries
and corruption controls. Until then those probes remain unbound. A separate
callee investigation would be required before assigning meaning to the
internal RPC call. No scope gate should advance on this evidence alone.

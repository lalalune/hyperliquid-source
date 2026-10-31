# Result: bounded consensus server evidence

Verdict: **strong for this bounded static census**, not a consensus server reconstruction. The digest-bound census is complete under the stated ELF RELATIVE Location representation and accepted instruction model. It has Location relocations, raw FDE transcripts, length-bearing literal anchors and decoded direct call edges; the selected diagnostic list is not an exhaustive string census.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 3 |
| decoded_instructions | 15212 |
| diagnostics_absent | 0 |
| diagnostics_bound | 19 |
| diagnostics_probed | 26 |
| diagnostics_unresolved | 7 |
| indirect_calls_unresolved | 772 |
| indirect_jumps_unresolved | 41 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 518 |
| location_leas | 54 |
| locations | 35 |
| pointer_length_anchors | 22 |
| scoped_fde_bytes | 81294 |
| scoped_fdes | 21 |
| scoped_rel32_calls | 4 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 26 |
| unresolved_external_rel32_calls | 548 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

## Diagnostics and literal anchors

A bound candidate has an exact-start RIP LEA in a scoped FDE followed by either adjacent stored pointer/length fields or a short non-clobbering pointer/length register setup ending in a call. This establishes bytes and local setup only, not a logging event or argument meaning. Occurrences, addresses, raw instructions and rejected setups are in `inventory.json`. Present-but-unbound means the exact probe appears somewhere in the ELF but no scoped setup passed the stricter binding rule; absence is a whole-file exact-byte search, not semantic absence. Reference probes are identified by byte offset, size and digest, without reproducing the unlicensed reference text.

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| server_listen_get_node_ip | bound | 25 | 1 | 1 |
| external_tx | bound | 11 | 6 | 2 |
| consensus | bound | 9 | 66 | 2 |
| firewall_ips | bound | 12 | 7 | 1 |
| validator_gossip_priority | bound | 25 | 1 | 1 |
| server_node_tcp_senders | bound | 23 | 1 | 1 |
| tx_hash_to_seq_num | bound | 18 | 4 | 1 |
| failed to load firewall ips | bound | 27 | 1 | 1 |
| failed to load node config | bound | 26 | 1 | 1 |
| Could not parse home public ip | bound | 30 | 1 | 1 |
| Refresher request | bound | 17 | 2 | 2 |
| Incoming tcp stream | bound | 19 | 1 | 1 |
| Dropping tcp stream | bound | 19 | 1 | 1 |
| Received rpc request | bound | 20 | 1 | 1 |
| Failed to receive response from rpc task | bound | 40 | 1 | 1 |
| Outbound response | bound | 17 | 1 | 1 |
| send consensus rpc resp | bound | 23 | 1 | 1 |
| Failed to send tcp response | bound | 27 | 1 | 1 |
| Refresher response | bound | 18 | 1 | 1 |
| reference-lead-1 | present-but-unbound | 26 | 1 | 0 |
| reference-lead-2 | present-but-unbound | 13 | 2 | 0 |
| reference-lead-3 | present-but-unbound | 13 | 2 | 0 |
| reference-lead-4 | present-but-unbound | 27 | 2 | 0 |
| reference-lead-5 | present-but-unbound | 17 | 2 | 0 |
| reference-lead-6 | present-but-unbound | 13 | 2 | 0 |
| reference-lead-7 | present-but-unbound | 29 | 2 | 0 |
<!-- END GENERATED LITERALS -->

## Direct edges

The following E8 rel32 instructions land exactly on other scoped FDE starts. Addresses and displacement are decoded from stored bytes; they do not prove execution or that other direct, indirect or vtable targets are absent. The JSON partitions every decoded rel32 transfer, and counts other indirect calls and jumps without resolving them.

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x203d330 | 0x203d8ea | e881ef2300 | 2355073 | 0x227c870 |
| 0x203d330 | 0x203dbc2 | e8f9e42300 | 2352377 | 0x227c0c0 |
| 0x22be860 | 0x22beae5 | e886ddfbff | -270970 | 0x227c870 |
| 0x22be860 | 0x22bedb3 | e808d3fbff | -273656 | 0x227c0c0 |
<!-- END GENERATED EDGES -->

## Constants

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| connection interval | unresolved | none |
| address-copy retry interval | unresolved | none |
| inactive-removal retry interval | unresolved | none |
<!-- END GENERATED CONSTANTS -->

These are categories motivated by the reference, with no promoted numeric value or units. Generic immediate co-location is insufficient to establish a server-specific role.

## Explicit non-claims

No runtime behavior, protocol semantics beyond bytes, source reconstruction, recovered function names, or coverage denominator. No claim for any other consensus file, slack_alert, spot_meta, spot_clearinghouse, evm_kvs, nv_stream, tokio, networking internals or generic foundation helpers. No helper, indirect call, relocation or data/vtable closure, build, whole-ELF equivalence, node #115 or visor parity. No gates are advanced. The static results are consistent with, but do not repeat, the specific prior [RE-008](../RE-008-consensus-wire-state/README.md) and [RE-009](../RE-009-storage-state-roots/hashers.json) claims.

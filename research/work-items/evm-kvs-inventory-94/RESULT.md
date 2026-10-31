# Result: #94 evm_kvs bounded static inventory

## Observations

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

Line/column pairs recur across large ranges; these are separate Location slots
and are counted separately. Each record has
at least one decoded LEA; raw relocations, instructions and owning unwind
records are in `inventory.json`. The containing ranges are not exclusive
component ownership and do not establish recovered source function boundaries.

E8 calls in `0x1fd6300` at `0x1fd64d8` and `0x1fd70a9` land at
`0x1fd7810`, each by signed rel32. They are static instruction facts; no
argument, effect or reachability claim follows. Other direct transfers are
counted but not attributed. Indirect edges remain unresolved.

Finite probes are bound to scoped LEAs by the byte patterns described
in the README. Anchors include pointer/length constructions and bounded counted-byte fragments;
multiple anchors can share one probe. For
example, `write_evm_kvs_batch` has a LEA at `0x1fd71df` followed by pointer
and length 19 stores, and `write evm kv batch` has a LEA at `0x1fd786f`
followed by pointer and length 18 stores. The counted chunks demonstrate
length and byte containment only. Shared ranges and literals do not establish
which source produced a message. The present-but-unbound probes are:
`RocksDb too large` and `evm_kvs_checkpoint`; `rocksdb bug` is absent as
exact case-sensitive bytes from the authenticated file. These latter probes were
catalogue hints; this does not validate reference labels or imply that a
case variant or equivalent logic is absent.

The numeric probes -1 and 8 remain unresolved. The decoded -1 adjacent to
`EvmKvsMsg` appears in multiple scoped constructions, so it fails the chosen
unique co-location rule; 8 lacks that construction. Neither value is assigned
a semantic role. Diagnostic and constant denominators are finite probe lists,
not all literals or constants in these ranges.

## Limits and non-claims

No runtime behavior, protocol semantics, source reconstruction, recovered
Rust, build, equivalence, validated function-coverage denominator or progress
gate is claimed. No claim is made about evm_rpc, evm_store, l1 EVM, nv_stream,
consensus, abci or generic foundation helpers. No call closure, indirect
calls, vtable/data closure, full relocation comparison, CFG reachability,
whole-ELF comparison or #115/visor parity is established. FDE extents are
unwind ranges; missing FDEs, inlining and shared ranges remain possible.
No behavior follows merely from a log-like string or numeric bytes.

Static verdict: **strong bounded evidence packet**, with a complete census for
the stated RELA Location layout, decoded LEAs, length-bearing anchors and
scoped call edges; this is a partial slice, not a reconstruction milestone.
The reference tree was unavailable for direct comparison. `make verify` and
`make reproduce` reached authenticated artifacts but failed on the missing
pinned can1357 reference binary. `make test` failed with errors, including tests requiring missing can1357
source files; it started
before the new focused tests were added. `make catalogue-check` reports a
stale generated `research/catalogue/components.json` in this checkout. No
input was fetched, and no generated catalogue was altered. The focused packet
tests and verifier pass independently.

# RE-008 / RE-001 / RE-005: Context hardfork decoder entry (#115)

**Partial, unvalidated research. Not ready for publication or a gate.**

Question: what are the first native dispatch and failure boundaries of the Context `hardfork` child at `0x32b03e0`? Target, pinned source, commands, actual tool versions, measured discovery time and remaining acceptance work are in `progress.json`. Evidence is static; the captured node was never executed. Imported disassembly retains the target artifact rights; no Rust reconstruction or licensing of the binary is claimed.

Integrated `RE-009-abci-binary-context-115` owns the Context map/sequence calls, not this callee body. Exact PRs #6663 and #6664 also exclude the called decoder body; these contributor statements are not maintainer authorization.

## Observations from the retained excerpt

- GNU readelf reports the FDE `[0x32b03e0, 0x32b182a)`. This is an unwind extent, not proof of a complete source-function boundary.
- At `0x32b03f4..0x32b0402`, the old input byte at `+0x20` is read, the field is set to 1, and old value 1 selects fresh-byte fetching. The old byte at `+0x21` is also read. Exact field types remain unknown.
- Fresh-byte fetching uses pointer `+0x10` and remaining count `+0x18`, decrementing count and advancing pointer. A zero count takes `0x32b042b`, stores byte 0 to output, then jumps to `0x32b0f6f`. That continuation has not been inspected; no complete return/error semantics are claimed.
- Fresh negative-byte comparisons route compact map-shaped markers to `0x32b04dc`, sequence-shaped markers to `0x32b0d3f`, and string-shaped markers to `0x32b0ec8`. Names are MessagePack interpretations; only selected route instructions are observed, not object validity or acceptance.
- Old state other than 1 reaches the signed-relative table dispatch at `0x32b0462..0x32b0474`, table VA `0x718010`. Entries and reachable state domain are not yet validated.
- The selected fallback preparation reaches indirect call `0x32b0486` through slot `0x64e3770`, then jumps to `0x32b14bd`. The helper and continuation are boundaries, not proven error/default behavior.

## Remaining work

Resolve the selected table, relocation and FDE-header joins with real-image proof and corruption controls. No new native excerpt is permitted by this bound. Root checks and independent validation remain unrun. No full hardfork decoder, consensus transition, source equivalence, complete helper closure, progress gate, hosted CI, container or runtime result is claimed.

## Data-only continuation and replay

Pinned source: `a8616af9432b8d8517b2af677880e117b7c28ef3`. Sole target node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No reference source code was copied. GNU binutils 2.40; remote Python 3.11.11.
All coordinates below are linked ELF VAs, not runtime rebased addresses.

`joins.json` records new data-only observations. Header row 46303 points at
FDE VA/file offset `0x11dada0`; CIE VA/file offset `0x103d604` has the retained
version1 zPLR encoding bytes. The decoded PC-relative start and 5194-byte range
agree with GNU readelf's earlier independent output. Entry VA `0x32b03e0`
corresponds to file offset `0x32af3e0`. The replay compares all 511 contiguous
retained instruction bytes with the authenticated real image, not another
model-derived implementation.

The 900-byte DATA window at `0x718010` ends at the next table base observed in
the sole native excerpt. Its 225 signed-relative values are retained by grouped
index in `joins.json`; this is NOT a proof of table extent or valid cached states.
The fresh-byte path reaches this table only for markers c0..df (32 possibilities);
13 of those entries route to `0x32b0477`. That route moves the marker to r8d,
restores the prior +0x21 byte into eax, and joins the call preparation at
`0x32b047c`. It is a fallback boundary, not an assertion of complete error semantics.
Index c1 instead points to uninspected `0x32b0eba`. Cached old state1 bypasses
the table; the valid/reachable domain of other cached states is unknown. No
out-of-domain state is characterized as a defect.

The observed helper slot `0x64e3770` is backed at file offset `0x64e1770` by zero
bytes and an ELF64 RELA R_X86_64_RELATIVE (type8, symbol0) addend `0x34013e0`.
The +8 slot similarly resolves to `0x33e2380`. These are relocation ownership
joins, not inspected helper bodies, recovered signatures or semantic closure.
No helper native excerpt was taken. No normalization mask is used.

Reproduce from repository root, using stdlib only and the pinned artifact:

```sh
python3 research/work-items/RE-008-context-hardfork-entry-115/replay.py
python3 -m unittest discover -s tests -p test_context_hardfork_entry115.py -v
```

`scoped.txt` records actual scoped execution. Controls change one real-image
instruction, table displacement, FDE extent, CIE encoding, relocation addend or
identity byte in memory and require rejection or a changed observation. They
are comparator controls, not claims that target software rejects such inputs.
The retained native sample remains one candidate and one 511-byte excerpt.
No full native decoding, Rust implementation, build equivalence, hosted CI,
container result, RE-008 dependency completion or component gate is requested.

The initial 'remaining work' list above describes the earlier partial snapshot;
data/FDE/relocation replay is now implemented, while cached-state reachability,
helper semantics and complete decoder behavior remain unknown. Root checks and
independent validation remain unrun. Concrete component-catalogue ID and final
packet review are still required before publication. Next native research, if
separately selected after this bounded task, should identify the cached-state
constructor/invariants rather than assume all byte values can reach this table.

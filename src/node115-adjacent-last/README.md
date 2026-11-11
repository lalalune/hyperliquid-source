# Node115 adjacent-key last-record compaction

Independent MIT no_std source for the complete call-free312-byte leaf
`0x5b2d510..0x5b2d648`, under the documented valid-memory premise.
See [contract/evidence](../../research/work-items/RE-001-adjacent-last-115/README.md).

`compact(&mut [Record])` keeps the last32-byte record of each adjacent run
whose leading20 bytes match. It returns an own new-length coordinate.
Nonadjacent repeats remain separate. Full backing-tail mutations match the
initial swap, subsequent duplicate swaps and distinct copies; the API neither
truncates nor erases the slice. A prefix-only first/last-wins dedup is not the
qualified full state relation. Original return type, record meaning, caller
ordering, original ABI and consensus validity are not asserted.

The fragment has no external dependency or invented Cargo workspace. Direct
host research builds use rustc1.94.1/edition2021 at opt0/3; no Linux execution,
original compiler, target-byte equivalence or complete node is claimed.

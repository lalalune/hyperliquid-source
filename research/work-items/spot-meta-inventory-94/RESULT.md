# Result: bounded static spot metadata inventory

**Verdict: strong for the stated byte-level census; thin for source ownership
and protocol interpretation.** Every exact-path Location relocation found by the
stated census has a decoded RIP-relative LEA and owning unwind range. The
bound literal probes have explicit pointer-and-length setups, and direct rel32
edges are retained as raw bytes and decoded destinations. These observations
are not an implementation or a complete component map.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 6 |
| counted_fragment_anchors | 0 |
| decoded_instructions | 139408 |
| diagnostics_absent | 2 |
| diagnostics_bound | 8 |
| diagnostics_probed | 12 |
| diagnostics_unresolved | 2 |
| location_leas | 599 |
| locations | 17 |
| out_of_scope_rel32_transfers | 5708 |
| pointer_length_anchors | 8 |
| scoped_fde_bytes | 697011 |
| scoped_fdes | 333 |
| scoped_rel32_calls | 269 |
| scoped_rel32_jumps | 1 |
| unique_line_column | 6 |
<!-- END GENERATED METRICS -->

The diagnostic denominator is the explicitly listed probes, not all
strings in the binary. Bound, present-but-unbound, and absent synthetic controls are counted above. Each status, occurrence, rejected candidate,
raw literal byte sequence and setup is in `inventory.json`. The numeric leads
remain unresolved: immediate occurrences, when found, do not establish a unique
labelled field or a meaning. The recorded calls and jump connect starts in the
Location-referencing FDE slice, which can contain inlined or shared code; their
scope is explicitly co-location, not exclusive authorship. The remaining direct
transfers leave that slice and are not attributed.

The reported records are observations, not inferred Rust function names or
semantic types. There is no claim about runtime behavior, protocol rules, source
reconstruction, source-to-binary equivalence, exclusive ownership, full CFG,
code without FDEs, or node #115/visor. This packet makes no claim for other source
files, generic helpers, data or vtables. It does not close helper calls, indirect
transfers, general relocations, data or whole-ELF identity. No comparison or
normalization was performed, and no progress gate is requested.

The next bounded question is whether a particular anchored range can be given a
validated CFG and data-flow interpretation that separates the inlined Location
from surrounding code, including its indirect calls and relevant data. That
requires further evidence; this packet does not assume the answer.

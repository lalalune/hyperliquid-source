# Node #115 open-PR integration validation

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The active PR review was blocked by malformed manifest separators and
historical root-document references resolving to newer or packet-local files.
`metadata-repairs.json` records the minimal metadata repairs. Original submitted
manifests and every affected historical root document are retained byte-for-byte.
The uncommitted CPython cache row is excluded from the active manifest; its
original declaration remains in the retained submitted manifest.

No raw binary evidence is rewritten, no instruction execution is claimed, and
no component reconstruction gate is advanced. Combined validation is pending.

The compaction-dump model now wraps packed integer lanes at their observed
widths. Boundary controls and the host-libc test corrections are recorded in
`review-corrections.json`; all 71 focused tests pass. These are bounded
research-model checks, not a reconstructed-node execution or identity claim.

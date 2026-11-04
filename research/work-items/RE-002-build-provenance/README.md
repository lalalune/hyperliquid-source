# RE-002: node #115 build provenance

The active target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`provenance-115.json` retains exact byte observations, inferred settings and
unknown build fields. The separate visor record is an optional provider-smoke
reference, not another node implementation target.

The node embeds rustc 1.95.0 / LLD 22.1.2 and vendored dependency paths. Exact
fork contents, Cargo locks and release flags remain incomplete.

Run `python3 tools/build_provenance.py --check` to reproduce both retained records.
Older release comparisons are recoverable through Git history.

The [node #115 CFA frame-policy packet](../RE-002-node115-cfa-frame-policy/README.md)
adds a two-native-tool census of 135,313 FDE records and complete selected
instruction evidence. It distinguishes saved RBP from RBP-based CFA; source/object
ownership and the build-wide frame-pointer setting remain unresolved, so the
generated `frame_pointers` field intentionally stays unknown.

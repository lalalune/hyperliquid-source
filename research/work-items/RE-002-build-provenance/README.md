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

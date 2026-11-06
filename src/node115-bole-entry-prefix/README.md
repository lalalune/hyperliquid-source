# Node115 private free-entry prefix

Independently authored MIT no_std logical reconstruction of the selected
entry prefix in `0x2c80670..0x2c80a3d`, not a whole Bole operation.
See the [contract and evidence](../../research/work-items/RE-001-bole-entry-prefix-115/README.md).

`prefix(Inputs)` retains ordered first-free selection, both preceding bounds,
zero-primary/raw2 handling and the header-dependent lookup frontier. Fields
and enum names are owned analysis labels. Floating input is copied as bits;
it is never calculated. Lookup helpers are not called or given fake results.
No counter update or later operation is composed. `None` refuses lengths
outside primary16/list32/secondary16, an own policy rather than native error.

The fragment uses direct rustc builds with no external crates, Cargo graph,
network or binary transplantation. Host research qualification uses
rustc1.94.1, edition2021, opt0/3. This is not a Linux node, original ABI,
compiler reconstruction, source-byte equivalence or complete component.

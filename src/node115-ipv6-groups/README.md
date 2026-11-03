# node115 bounded IPv6 group reader

Independent MIT reconstruction of the477-byte group reader and actual fixed-
configuration numeric/IPv4 helper composition. The own API accepts capacity0..8,
mutates a cursor and eight-word output array, preserves unused words and failed
separators, and reports count/IPv4-tail indication. It does not expand :: or
implement the whole IPv6 parser/imports. Only final memory effects are compared.

The IPv4-prefix helper algorithm is reused from the project's own MIT PR2334
at source eb0b4600, with provenance in the evidence packet; it is not new recovery.
See [the packet](../../research/work-items/RE-012-ipv6-groups-115/README.md)
for exact115 SHA, pre-Rust freeze, raw caller/helper records, corruption controls,
research compiler/build commands and unresolved original ABI/valid-state scope.
No root Cargo workspace or recovered dependency graph is invented.

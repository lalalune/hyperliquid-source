# Node115 logical HTTP header writer

A dependency-free, safe `no_std` library for the complete ordered header-byte
append operation related to node115 `0x2e77070..0x2e7792e`.

`append(primary, spelling, capitalize, output, used)` performs tagged-name lookup,
pairs spelling occurrences, applies optional ASCII title casing only to fallback
names, and writes ordered header lines. Empty values omit the space after the
colon. It allocates nothing, preserves the existing prefix and unused suffix,
and preserves the entire output buffer on every returned error.

Global validation checks used bounds, group counts, ordinals, nonempty groups,
duplicates, representation-size bounds, required-length arithmetic and capacity
in that order. These atomic refusals are host policies. Custom names and values
are arbitrary bytes; this is not an HTTP grammar validator or network stack.

The [evidence packet](../../research/work-items/RE-012-node115-logical-header-writer/)
contains the full conditional native relation, prior credit, frozen literals,
actual debug/release tests, semantic variants, static replay and preserved first
failures. Native correspondence assumes coherent physical map/cache/probe and
finite chain invariants plus ordinary helpers; no hash/feed implementation,
native ABI, allocator failure or captured runtime equivalence is claimed.
New code is MIT.

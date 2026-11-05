# Node115 tier selection

Independent MIT no_std source for the qualified ready-global, inline-tree and
sorted-ring relation at `0x3c43150`, including actual search dependency
`0x4556c50`. See the [contract/evidence](../../research/work-items/RE-001-perp-tier-selector-115/README.md).

`select(Inputs)` returns three raw words plus exact row-origin/byte-offset
identity, or stops at a named initializer/diagnostic frontier. New safe types
are logical labels, not original Rust enums, layouts or borrowed field types.
Source ring search performs bounded binary search in logical sorted order;
the original two-span search is evaluated in the native oracle, including its
real CALL/RET. Only its successful location is observed by this caller; no
miss insertion index is exposed or invented. Unused ring storage is ignored.

`None` refuses input outside the documented finite shape/sortedness domain;
that is an own API policy, not native malformed-container rejection. Guard,
row fields and storage are supplied premises. No original global values,
initialization result, diagnostic effect or caller validity is assumed.

Direct rustc research builds use edition2021/rustc1.94.1 on macOS arm64, with
no external crates or invented Cargo workspace. A successful host build is
not a Linux node build, original ABI, target-byte identity or component gate.

# Node #115 validator epoch ring

This dependency-free Rust crate models the logical search result of the
validator epoch ring routine in node #115, binary SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`search` receives a physical ring slice, its head, live length, and an epoch.
It returns the first matching logical index or the logical insertion index.
The target evidence records the native result as `al = 0` on hit and `al = 1`
on miss, with the logical index in `rdx`. The crate rejects malformed value
views with host-only `Bounds` and `Order` errors; those errors are not native
error behavior.

The algorithm was independently expressed as lower-bound search over the live
logical view. This preserves the target's externally observed search results,
including wrapped storage. It does not reproduce the native pointer layout,
ABI, branch sequence, or memory-access profile, and the Rust tests are not a
binary comparison. For the target-grounded interpreter evidence, cases,
negative controls, and known gaps, see
[`staking-validator-snapshot-lookup-115`](../../research/work-items/staking-validator-snapshot-lookup-115/README.md)
and especially its ring epoch search section.

Build and run the crate checks with Rust 1.95.0:

```sh
cargo test --offline --locked --manifest-path src/node115-validator-epoch-ring/Cargo.toml
```

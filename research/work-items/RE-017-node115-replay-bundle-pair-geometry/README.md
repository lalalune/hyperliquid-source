# RE-017 · Match replica bundles to #115 preflight descriptor slots

The repository's apply-block input fields `header_actions` and `payload_actions` stand for counts at the **bundle** level in this guard. A first-block fixture with two bundles and three individual signed actions needs two native payload descriptor slots to satisfy that comparison.

Linux x86-64 #115 artifact SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `2da45cb0a761cff6b478e40421699857d87a94df`. [Replica bundle JSON](../RE-017-node115-replica-bundle-json/README.md) identifies a 40-byte source entry per emitted bundle. [Apply-block guards](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md) identifies the inequality branches. This packet traces the compared lengths through both readers and follows the paired layout to the first descriptor decision.

- The block field writer passes the block base at `0x4d6d636` to the outer `signed_action_bundles` writer. That writer reads the array pointer from `+8` and the count from `+0x10` at `0x5075e3a` and `0x5075e3e`. The nested `signed_actions` array uses a separate pointer/count load at `0x5090897` and `0x509089b`.
- The compact reader stages third argument `D` and nested block pointer `B = [D+0x18]`. The guard reads `[B+0x10]` and `[D+0x10]` at `0x5a04f29` and `0x5a04f3d`. Inequality reaches `0x5a06290`. The expanded reader repeats the same two offsets and branches to its distinct diagnostic at `0x5a07af2`.
- For the selected nonempty compact path, `[B+8]` is the 40-byte-entry base and `[D+8]` is the 24-byte-descriptor base. The compact setup computes both ends from the checked count before it pairs positions. The two readers advance by 40 and 24 bytes respectively. Both inspect the leading qword of the selected descriptor and branch to a separate continuation when it equals `0x8000000000000000`. The equality check establishes equal slot counts before this decision; it does not imply each descriptor represents a successful bundle. The packet leaves downstream marker handling and descriptor production open.

[project.py](project.py) supplies the two guard values from separate inputs and keeps the nested count for auditing. Under the existing Rust field names, use `header_bundles` for `header_actions` and `payload_descriptors` for `payload_actions` when modeling this preflight comparison. The loader-side descriptor count must come from the independently acquired replay input; copying the archive count into both fields would mask a mismatch. The current Rust callback loop is outside this packet's scope.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-bundle-pair-geometry/verify.py
```

The verifier authenticates raw instructions from the pinned ELF and FDE extents, checks both mismatch edges and paired strides, and exercises ordinary multi-action, empty-inner and empty-outer fixture shapes. The [offline log](offline-log.txt) records the actual run. Checking the layout and comparing counts are the only modeled operations.

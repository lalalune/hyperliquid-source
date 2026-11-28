# RE-017 · Verify per-bundle prepared lengths for node #115 replay

A first-block fixture may have the correct outer bundle count and the correct total action count while still passing the wrong inner lengths to replay. The selected native preparation lane checks the expected length of the outer collection and of each inner collection before committing the output lengths. The fixture now checks both levels separately.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

| Boundary | Evidence for the successful length contract |
| --- | --- |
| Outer length source | The archive writer receives the block base and reads its outer count at `+0x10`. The selected preparation wrapper at `0x59edc8c` copies the message's pointer/count from `+8/+0x10`. Its trampoline passes the count to the outer collector at `0x4301e90`. |
| Inner length source | For each 40-byte bundle entry, both paths load a child pointer from entry `+0x20`. The archive writer advances the child by `0x10`, and its signed-action-array writer reads that value's `+0x10`. Preparation copies the pointer/count pair from child `+0x18/+0x20` into the inner trampoline, which extracts the count. The two count routes meet at child `+0x20`. |
| Inner commit | The selected inner collector at `0x4301ce0` prepares 112-byte result entries. It compares the collected count with the requested count at `0x4301dba`; successful return adds that count to the saved working vector length. The outer fold copies the resulting 24-byte vector descriptor into the group's indexed output slot. |
| Outer commit | Indexed setup in `0x3ec1b80` advances by 40-byte input bundles and 24-byte output descriptors. The outer collector checks its collected count at `0x4301f6e` before committing the length at `0x4301f94`. The wrapper returns the length at output `+0x10` and the original message pointer at `+0x18`. |

[Slow driver preparation](../RE-008-slow-abci-apply-115/README.md) mapped the two collectors and their input strides. [PR #7330](https://github.com/lalalune/hyperliquid-source/pull/7330) mapped outer descriptor pairing at apply-block preflight. The bounded addition is the source join and the two success-only length comparisons and commits. The proof covers normally returning selected preparation. It leaves alternate thread-pool entry branches and the contents and meanings of the prepared entries outside the fixture.

[check_shape.py](check_shape.py) accepts one archived replica row and an independently observed JSON array of prepared lengths in bundle order. Its output identifies the positions with a mismatch. Counts `[2,1,0]` and `[1,2,0]` have the same group count and sum, but fail at positions zero and one. An explicitly empty prepared group still occupies an outer slot. The observed counts come from the separately prepared fixture. Deriving them by copying the archive's counts would remove the independent comparison.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-prepared-geometry/verify.py
```

The verifier reads the pinned ELF as data, validates FDE extents, call edges and the count-source operands, and runs the offline CLI on synthetic matching and mismatching rows. See [the recorded run](offline-log.txt). This checks pre-execution shape only.

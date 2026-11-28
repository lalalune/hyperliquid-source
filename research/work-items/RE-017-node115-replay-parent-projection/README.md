# RE-017 #115 replay comparison words from the Block parent

This binds the selected replay Block comparison to the first two positional u64 scalars of a decoded quorum certificate. The third direct-quorum scalar and the leading timeout scalar feed the separate saturating successor. The existing [Block gate evidence](https://github.com/lalalune/hyperliquid-source/pull/7247) gives the owner offsets, and the [ClientBlocks grammar](../RE-001-node115-client-block-success-grammar/README.md) gives the wire order. This packet joins those two layouts so an offline replay can derive the observed pair from a decoded Block.

Let A be the Block owner. The inline success path of `0x4eff5f0` puts the Block result at A+0x10. The Block decoder `0x4fb7760` places the relevant parent region of the Header at the same relative offsets in its output. Consequently A+0x28 tests Header+0x18, and A+0xb8 tests Header+0xa8.

| Decoded Block parent | Read from the Header for comparison | Wire source | Successor basis before saturating increment |
| --- | --- | --- | --- |
| Direct quorum | +0x40 / +0x48 | First two scalars, from QC result+0x20/+0x28 via `0x59d6190` | Header+0x50, the third QC scalar |
| Timeout with no optional QC | +0x38 / +0x40 | First two scalars of the timeout certificate's embedded QC | Header+0xa0, the first timeout scalar |
| Timeout with an optional QC | +0xc8 / +0xd0 | First two scalars of the optional QC, copied by `0x4e05180` | Header+0xa0, the first timeout scalar |

The QC reader stores the first three successful scalar reads at result+0x20/+0x28/+0x30. The timeout reader preserves those embedded QC offsets and stores its own leading scalar at result+0x88. The optional QC reader uses the native absent marker, which the Header stores at +0xa8. The separate [spawn input trace](https://github.com/lalalune/hyperliquid-source/pull/7248) owns the expected side of the comparison. These observations preserve positional names for the words. A real capture would still be needed to bind their values to a checkpoint and verify a root.

The Rust function `replay_parent_projection` derives the pair and successor from the already typed parent. It works on the existing Block-or-Tx codec output and leaves the wire decode unchanged.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-parent-projection/verify.py
cargo test --locked --offline --manifest-path src/node115-client-block-success/Cargo.toml
```

See [raw output](offline-log.txt) and [selected ELF witnesses](windows.txt).

# RE-017 #115 direct loader stores in compact restore fixtures

The [compact image assembler](https://github.com/lalalune/hyperliquid-source/pull/7375) stops at the materializer result. After the native normal height check succeeds, the [ordinary loader](../RE-016-state-load-chain-115/README.md) writes several fields around separate initialization calls. This offline adapter applies one selected group of direct stores at a time to an input image whose identity and embedded height are pinned.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

| Fixture input stage | Direct state writes |
| --- | --- |
| `entry` | Compare compact `+0x28` with requested H. Store H at `+0x10`, saturating-increment the word at `+0x18`, copy the round from `+0x30` to `+0x20` and `+0xdf0`, and clear exactly eight bytes at `+0x10e8`. |
| `after-c-staking` | After calls at `0x3c12923` and `0x3c1292b`, reload the round from `+0x30` in the supplied image and copy it to `+0xef8`. |
| `after-action-delayer` | After the companion initializer and action-delayer helper, clear two bytes each at `+0x3e28` and `+0x3ee0`, and write byte 2 at `+0x39b0`. |

The second boundary rereads the newly supplied image because the native store follows two [c_staking calls](https://github.com/lalalune/hyperliquid-source/pull/7325). The final group follows the separate calls at `0x3c12946` and `0x3c12953`. The adapter accepts a different image at every boundary to leave the actual helper results explicit. It does not assume any of the helpers preserves the early round or the bytes surrounding those stores. The image-height check at later stages pins the intended fixture coordinate. This does not assert that native code repeats the entry height guard.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-loader-write-fixture/verify.py
python3 -B research/work-items/RE-017-node115-loader-write-fixture/test_writes.py
python3 -B research/work-items/RE-017-node115-loader-write-fixture/apply_writes.py \
    compact.bin --sha256 EXPECTED_INPUT_SHA256 --height H --stage entry > after-entry.bin
```

For later stages, supply the pinned image at the corresponding helper return. Tests compare all three groups with the existing pure loader model for 40 normal cases where helper stubs leave the image unchanged. Separate cases supply a changed round at the second boundary, check exact store widths, and read an actual local synthetic input file through the CLI. The original bytes, branch and helper slots are checked by the verifier. See the [offline log](offline-log.txt).

This fixture writes only the directly observed fields in the supplied byte image. It does not decode an original checkpoint, run native initialization, or establish H/H+1 ABCI root parity.

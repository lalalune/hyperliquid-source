# RE-017 #115 replay Block identity gate

The Block branch of the selected replay consumer checks two words against its future before it stages the Block and optional attachments. This extends the [zero-first-word Tx route](../RE-017-node115-replay-enqueued-payload-source/README.md) through the other arm of the branch at `0x5a8729e`. The [payload-pair evidence](../RE-017-node115-replay-payload-pair/README.md) establishes that a non-null first owner comes from the Block variant on the selected producer path.

Let F be the replay future at entry `0x5a82670`, A the first owner and B the optional second owner returned by the selected slot. After the return-tag gate and the existing pair copy, F+0x2d60 holds A and F+0x2d68 holds B. A zero takes the existing Tx route. Otherwise the consumer stages A/B at F+0x2d70/+0x2d78 and selects a base inside A. Here M is the raw marker `0x8000000000000001`.

| Condition in order | Two qwords loaded from A |
| --- | --- |
| A+0x28 equals M | +0x50 and +0x58 |
| A+0x28 differs from M, A+0xb8 equals M | +0x48 and +0x50 |
| Both marker comparisons differ | +0xd8 and +0xe0 |

At `0x5a874b9` and `0x5a874c6` the two words must equal F+0x100 and F+0x108 respectively. Either mismatch branches to `0x5a88aff`, which passes both pairs to the helper through slot `0x64e80e0`. The following edge reaches `ud2` if the helper returns. Only the matching continuation reaches the evidence below.

On that continuation, the code takes a separate word at A+0x60 when A+0x28 equals M, otherwise at A+0xb0. It increments the word, maps wrapping zero to all ones, and stores the result at F+0x1b0. The staged A/B pair is copied to F+0x1d8/+0x1e0 and then F+0x1b8/+0x1c0 for the subsequent consumer state. These are address and arithmetic observations. The producers and source-level names of the expected words at F+0x100/+0x108, the meaning of each word inside A, checkpoint binding and final root acceptance remain open.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-block-identity-gate/verify.py
```

The verifier reads the pinned ELF as data, checks FDE membership and byte witnesses, and recomputes the effective identity offsets and branch destinations. See [the recorded run](offline-log.txt) and [selected instruction windows](windows.txt).

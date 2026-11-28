# RE-017 #115 replay reader limit initialization

The first selected poll of producer `0x5a806f0` writes **10,000,000** at +0xe8. The producer carries that value through a copied reader image, then supplies it both to its TCP reader and to the replay payload decoder. This closes the input field left at producer+0x680 in [the compressed completion work](https://github.com/lalalune/hyperliquid-source/pull/7244). It gives a concrete bound for an offline model of this producer's reader and decompression input. The observation covers this initial-state path only.

Let W be the base of the producer future.

| Site | Observed dataflow |
| --- | --- |
| `0x5a80709–0x5a8071e`, `0x5a80ef9–0x5a80f30` | State zero at W+0x918 selects `0x5a80ef9`. The branch supplies W in RAX and jumps to `0x5a808d8`. |
| `0x5a80918–0x5a80931` | Writes 10,000,000 at W+0xe8, W itself at W+0x330, and clears the byte at W+0x338 and word at W+0x341. |
| `0x5a80972–0x5a80b25` | Copies 0x280 bytes from W+0xc8 to W+0x350, then to stack+0x958 and stack+0x160. The immediate is at relative offset +0x20 in this image. |
| `0x5a80b98–0x5a80bc2` | Copies the 0x2f0-byte aggregate at stack+0xf0 through stack+0x668 to W+0x5f0. The reader-image suffix starts at W+0x660, so the immediate lands at W+0x680. W and the two initialized zero fields map to W+0x8c8, W+0x8d0 and W+0x8d9 respectively. |
| `0x5a80c1c–0x5a80cb9`, `0x5ab43db–0x5ab57c1` | W+0x8d9 equals zero on that initialization path and selects `0x5a80c33`. The producer copies the immediate to W+0x6b0 and passes W+0x690 as the reader base. The reader moves input+0x20 to its +0x28 and later loads it as the LZ4 adapter's fourth argument. |
| `0x5a80c48`, `0x5a80db8–0x5a80de7` | The same value is preserved separately at W+0x688 and supplied in RCX to `0x5860bb0` on the selected decode path. The replay decoder's internal use of that argument is outside this observation. |

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-replay-reader-limit-origin/verify.py
```

The verifier hashes the pinned ELF, checks the two zero-state jump-table entries, resolves the dynamic `memcpy` binding, and recomputes the copied offsets from the encoded operands. See [raw output](offline-log.txt) and [selected instruction windows](windows.txt).

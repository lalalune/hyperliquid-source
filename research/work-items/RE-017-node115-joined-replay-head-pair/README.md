# RE-017 #115 replay comparison pair on the joined startup path

On the selected startup join, the Block comparison's expected pair comes from the head of the state given to the direct builder. The builder carries offsets +0x18 and +0x20 without the patch performed by the separate loader wrapper. The join also checks a third word at +0x28. Using that comparison to infer either member of the expected pair would conflate separate fields and two different call paths.

| Boundary | Observed relation |
| --- | --- |
| Join selection | `0x5646881` reads the state pointer from the joined object's +0x18. The selected tag-`0x44` source arm compares the state's +0x28 to the saved third join argument at `0x56469fe–0x5646a09`. Equality continues to `0x5646ba2`, which passes the pointer directly to builder `0x3c13610`. |
| Builder copy | Via `0x3c13665`, the materializer at `0x3c2e860` copies the first 0xba0 bytes directly from input to output at `0x3c2f00a`. This includes both qwords and the separate +0x28 word. The builder copies 0x42c8 constructed bytes into the returned allocation at `0x3c13689`. |
| Expected replay inputs | The [joined startup return](../RE-012-node115-joined-state-provenance/README.md) carries the builder pointer in join result+8 and outer result+0x30. The [replay spawn input trace](https://github.com/lalalune/hyperliquid-source/pull/7248) reads +0x18/+0x20 from that allocation at `0x2af579c` and carries the words to the Block gate's future+0x100/+0x108. |
| Separate restore path | Loader `0x3c12800` compares loaded state+0x28 to the request, then saturating-increments +0x18 and copies +0x30 to +0x20. The selected join calls the builder directly. The [loader result packet](../RE-017-node115-replay-key-source/README.md) covers the separate wrapper path. |

The claimed equality between the input and later read is conditional on the selected normal returns and no intervening writes to the two words through aliases. The join invokes a digest helper with the boxed pointer before returning it. This packet covers the direct builder copy and pointer handoff, and makes no claim about all digest-helper or asynchronous side effects. The joined object's upstream persisted values, the provenance of the third join argument, the other caller's inline pair and the state root of an actual replay remain open.

## Offline verification

From the repository root run:

```sh
python3 -B research/work-items/RE-017-node115-joined-replay-head-pair/verify.py
```

The verifier checks the pinned ELF, FDE bounds, selected encodings and relocation endpoints, then verifies the copy coverage and the distinct loader field offsets. See [raw output](offline-log.txt) and [selected instructions](windows.txt).

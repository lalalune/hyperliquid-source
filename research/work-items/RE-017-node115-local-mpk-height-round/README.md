# RE-017 #115 local MessagePack Context height and round

Component `abci`. The local startup MessagePack Context has its own field-name selector and scalar readers. On the selected object return, it preserves `height` at output +0x28 and `round` at +0x30, separately from the [hardfork pair](../RE-017-node115-local-context-hardfork/README.md) at +0x18/+0x20.

- The field-name selector at `0x27401e0` returns index 2 for `height` and index 4 for both `round` and `consensus_round`. The two round names reach the same guard, so the second name cannot provide an independent round value. The one-byte mutation `consensus_roune` returns unknown index 13.
- The round arm calls `0x2d15bc0`. Tag 9 stages its payload at stack+0xd8 and marks the value present at stack+0x138. The map exit substitutes zero if that presence bit is clear.
- The height arm calls unsigned reader slot `0x64e2580`. Tag 9 stages its payload at stack+0x198 and marks presence at stack+0x100. The selected normal return is gated on that presence bit.
- Stores `0x1b3fc8a` and `0x1b3fc8e` write the two words independently. The successful Locus caller copies the contiguous pair from stack+0xc98 to stack+0x480.

This selected local decoder evidence complements [the checkpoint lane](../RE-017-node115-checkpoint-round-source/README.md), which enters a different Context visitor. It provides separate scalar inputs for local startup fixtures. This route has no observed conversion from the decoded height word to the decoded round, and the packet ends at the Locus staging copy. Actual checkpoint values and state-root equality remain open.

## Offline verification

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-mpk-height-round/verify.py
```

The script checks the pinned ELF and FDE spans, selected control transfers and exact value stores, and evaluates the four bounded field-name probes from the selector instructions. See [raw output](offline-log.txt) and [instruction windows](windows.txt).

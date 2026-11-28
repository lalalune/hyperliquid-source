# RE-009 Node #115 restored quorum rows, pending times and watermark

A normal MessagePack checkpoint restores quorum rows, pending timers and the quorum watermark from the `exchange.advt` subrecord. These values matter to an offline replay that starts from a checkpoint. Starting all three empty discards state the node carries into the next block. The [prior reader packet](../RE-017-node115-replay-delay-checkpoint-read/README.md) established the subrecord and the `adu` delay word. This packet follows the three adjacent fields with different consumers.

- Component: `storage` / `abci`.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c2772e3b1c742734af159c2c42c9541c7ebb7ac2`.
- Method: LLVM objdump 23.1.4, Intel syntax, ELF virtual addresses. The verifier checks the pinned ELF directly.

## Selected keyed reader

The parent passes the recorded `advt` value to `0x33b2a30`. Its map helper `0x303c300` returns tag 9 and dispatch index 7 when no map pairs remain. Relative table `0x765648` then enters the record-completion block at `0x33b35e0`. Earlier iterations decode fields and stage their values for that completion block.

| Field | Table index and value helper | Staged value and offset in the returned 0xb8-byte subrecord |
| --- | --- | --- |
| `qrs` | 1, `0x3259070` at `0x33b2fc2` | The tag-9 result stages a leading qword at stack `+0x10` and 16 following bytes at `+0x158`. The completion block joins the qword at `+0x150` with those bytes, then copies the three words to record `+0x48`. The selected omitted-field route invokes the named `qrs` diagnostic. |
| `highest_quorum_height` | 2, slot `0x64e2580` at `0x33b2e4a` | Tag 9 carries a full qword from result `+8` to stack `+0x3b8`. That qword reaches record `+0x80`. Completion checks a distinct field-presence byte, so a present zero keeps its value. An omitted field uses the named diagnostic. |
| `htm` | 3, `0x3223900` at `0x33b2c92` | The selected decoded descriptor is staged at stack `+0x280` and copied in two 16-byte lanes to `+0x230`. When the field was omitted, the completion block instead initializes those four qwords to `{0, 8, 0, 0}`. Either normal route copies this slot to record `+0x60`. |

The diagnostic key bytes independently identify the handlers. The outer copy verified in the earlier reader packet places the tracker at historical state `+0x2330`. Materializer `0x3c2e860` copies all 0xb8 bytes to live `+0x3e50`. The fields therefore reach live offsets `+0x3e98`, `+0x3ed0` and `+0x3eb0` respectively.

## Replay consumers

At `0x548bf4b`, replay finalization passes state `+0x3e50` to `0x5afa030`. This helper passes tracker `+0x60` to the timer fill helper and takes the descriptor at tracker `+0x48` afterward, replacing the latter with an empty descriptor. The selected updater `0x5afa3b0` preserves the larger of the existing watermark at tracker `+0x80` and the incoming height. This watermark is a separate word from the pending descriptor's `+0x78` input to the drain cutoff.

This evidence binds the field names to the selected restored slots and their consumers. The nested collection entry encodings, alternate formats and a real checkpoint/root pair are outside this packet. The selected absent-field branches establish whether a default is synthesized directly on this route. They do not establish behavior for every alternative accepted by scalar or collection helpers.

## Reproduce

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-quorum-tracker-map/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)

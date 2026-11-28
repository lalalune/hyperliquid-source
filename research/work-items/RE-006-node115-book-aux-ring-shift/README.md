# RE-006: 24-byte auxiliary-map ring move helper

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Static observations and interpretations only. No captured executable is run or emulated and no component gate is claimed.

## Question and prior work

[#7851](https://github.com/lalalune/hyperliquid-source/pull/7851) identifies a flat auxiliary-map removal caller that chooses a side to shift and calls `0x5817e50`, but leaves that helper opaque. How does the called routine handle a 24-byte row move, including a wrapped case? The selected caller uses capacity, buffer, source index, destination index and count in the SysV argument registers. Generic ring-copy observations in other map instances do not establish this helper's FDE or dynamic import.

## Static evidence and interpretation

The full FDE is `0x5817e50..0x5818125` (725 bytes). At entry the helper subtracts source index from destination index; equal indices or zero count return without entering the move cases. Otherwise it derives distances from capacity to source and destination and dispatches through several unsigned comparisons. The retained caller window `0x4da894f..0x4da8999` shows its side-selection branches and direct call to this helper; valid ring state and ordinary SysV argument conventions are premises.

One path beginning at `0x581800e` computes `buffer + 24*source`, `buffer + 24*destination` and `24*count`, then tail-jumps through slot `0x64df568`. The ELF dynamic relocation for that slot identifies the imported symbol `memmove`. Other branches prepare two or three move calls with separate lengths and ring-base adjustments before converging on a final tail jump. For example, the `0x5817eaa..0x5817f24` path makes two direct calls through that same slot and prepares a third; the `0x5817f9c..0x5818009` path likewise computes three segments. The preserved complete instruction rows permit independent review of the other cases; this packet does not claim a complete mathematical proof for all wrap and overlap combinations or execute any of them.

`records.json` retains the entire 725-byte helper and a 74-byte caller window: 799 bytes / 220 decoded instructions across two FDEs. Fifty-seven static facts include nine RIP-relative references to the same slot and its dynamic relocation/symbol, plus 23 in-memory opcode, operand or relocation mutations. These checks bind the selected evidence to the authenticated ELF; they do not execute the target or compare target behavior to a model. `offline-log.json` contains the actual output.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-ring-shift/verify.py
(cd research/work-items/RE-006-node115-book-aux-ring-shift && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes each selection from its FDE boundary. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

Caller selection is limited to the single flat removal path; no complete caller census is claimed. Ring bounds, capacity and overlap invariants are assumed, and the dynamic loader's runtime binding is not observed. The multi-segment branches, error/unwind behavior, other instantiations and end-to-end map correctness need independent validation. Next, derive a full case table for the wrapped paths and compare the inferred cases with an independently authored ring model while keeping target behavior claims limited to static evidence.

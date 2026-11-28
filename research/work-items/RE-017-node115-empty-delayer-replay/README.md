# RE-017 #115 empty action-delayer replay extractor fixture

This packet carries the empty action-delayer state past the compact replay-begin call at `0x5483e4a` into its extractor result and consumer range. [#7417](https://github.com/lalalune/hyperliquid-source/pull/7417) normalizes a different quartet during restore. [#7402](https://github.com/lalalune/hyperliquid-source/pull/7402) projects selected replay-begin stores but leaves the extractor's effects open. [#2231](https://github.com/lalalune/hyperliquid-source/pull/2231) documents selected static extractor windows. This packet projects the complete selected ordinary-empty extractor path into an independently pinned local fixture.

Let `P = state + 0x40c0` be the compact subobject passed by the caller. The fixture scope is zero capacity, head and count at `P+0`, `P+0x10` and `P+0x18`, with an explicitly supplied aligned nonzero pointer word at `P+8`. The fixture does not dereference pointer words. The static route assumes valid, nonaliasing native object and call arguments.

1. The non-sentinel zero-count route at `0x3bed93e` passes length zero to `0x3d5c5d0`, which returns zero before inspecting the comparison key.
2. At `0x3bedae0` the empty temporary uses pointer word 8. The selected import call at `0x3bedb69` has length zero. The resulting four qwords written at `0x3bede01` and `0x3bede06` are `(0,8,0,0)` at `P+0..P+0x20`.
3. The kind-2 collection input has three zero counts at offsets `0x20`, `0x48` and `0x68`. The entry helper `0x3d73f20` reaches `0x3d740c6` and stores tag 2. The collector `0x3d6c090` returns `(0,8,0)` through its empty result arm. The selected cleanup calls return without freeing a buffer or reading queue rows.
4. At `0x3bedeb6` the extractor subtracts the zero result count from the `P+0x60` counter. The counter retains its value, and the remaining record-processing block is bypassed. The caller at `0x5483e50..0x5483e75` reads the extractor header and computes an equal-start/end range with stride `0x148`. The first four consumer descriptor words are `(8,8,0,8)`. Its fifth word comes from the state pointer and is outside the fixture output.

From the repository root:

```sh
packet=research/work-items/RE-017-node115-empty-delayer-replay
python3 -B "$packet/verify.py"
python3 -B "$packet/test_project.py"
python3 -B "$packet/project.py" compact.bin --sha256 EXPECTED_SHA256 --height H
```

The command prints the projected fixture digest and the two raw descriptors. The API returns the transform result bytes. It checks fixture size, exact digest, height and input shape. This verifies the selected offline state transition, with no captured instructions executed. Real checkpoint contents, the expanded caller, populated action queues, the consumer's internal behavior, and H/H+1 root parity remain open.

# RE-017: selected replay slot sequence-gap return

Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#6767](https://github.com/lalalune/hyperliquid-source/pull/6767) records the first-lock matching-sequence path of helper `0x59640e0`. This packet addresses a distinct selected second-lock mismatch path and its immediate return mapping in `0x59d6520`.

After the second slot lock, `0x596418e..0x596419a` compares slot `+0x28` against the descriptor cursor C. On mismatch it reads count N at shared object `+0x18`; if `(slot_sequence + N) mod 2^64 != C`, the selected normal-unlock continuation computes F = `(object[+0x30] - N) mod 2^64`. At `0x5964203..0x596428a`, F equal to C returns internal `(3, S)` and increments C; otherwise it writes F to the descriptor cursor and returns internal `(2, F-C mod 2^64)`. On normal release of the held slot lock the return reaches the caller. `0x59d6544..0x59d657d` dispatches internal index 2 to output `(1, 1, delta)`, whereas index 3 follows the nested-pointer path recorded in #6766.

This is a conditional machine-level result, not an assertion that the delta is a valid missing-block count or checkpoint height. It assumes the stated second-lock path, readable stable objects, normal unlock returns and the displayed modular arithmetic; the equality branch, lock contention, concurrent modification, initialization, producer-side meaning and actual replay reachability remain open. No target execution or completion gate is claimed.

Run `python3 research/work-items/RE-017-node115-replay-slot-sequence-gap/verify.py` for digest, selected instruction anchors, dispatch table entry and mutation controls. `windows.txt` contains static disassembly.

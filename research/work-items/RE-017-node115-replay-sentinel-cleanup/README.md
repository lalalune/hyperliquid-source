# RE-017 · Replay descriptor sentinel cleanup

The replay worker at `0x5a7034f` calls the cleanup at `0x5a5ce30`. The cleanup first checks the leading descriptor word and, if nonzero, passes +8 and 32 times that word to the shared indirect slot. It then distinguishes three values at +0x20 using the flags from NEG. Zero returns. Ordinary nonzero values tail-call the slot with the pointer at +0x28 and the value scaled by 32. The signed minimum `0x8000000000000000` instead builds iterator scratch records from the adjacent fields. The selected loop calls `0x51e48d0` and repeats while the returned first word is nonzero.

This establishes the descriptor-specific cleanup dispatch and explains why interpreting the sentinel as a buffer count would lose an entire cleanup path. The iterator internals, accepted descriptor values and runtime ownership remain open. The existing queue publication packet supplies context for the iterator callee.

From the repository root run `python3 research/work-items/RE-017-node115-replay-sentinel-cleanup/verify.py`. It binds the capture digest, verifies the complete function extent, pins both call targets, and rejects a mutated worker edge.

# RE-017 · Replay tagged handle cleanup

The replay worker calls `0x5a45720` at `0x5a7057f`. A +8 word equal to `0x8000000000000001` returns immediately, before touching the pointer at +0. Other values perform a locked decrement on the word at that pointer. A resulting zero enters a separate indirect call. On continuation the routine reloads +8. A value of `0x8000000000000000` tail-transfers the descriptor at +0x10 to `0x52489e0`. A zero word returns, and the ordinary nonzero branch passes the pointer at +0x10 and 16 times the reloaded word to the shared cleanup slot.

The two adjacent high-bit tags have different effects, including whether the counter is touched. The packet records the exact guard, atomic operation and alternate cleanup ABI. It leaves the pointer type, the indirect call's effects and the full concurrency contract open.

From the repository root run `python3 research/work-items/RE-017-node115-replay-tagged-handle-cleanup/verify.py`. The verifier checks the pinned image digest, full FDE, caller edge and mutation, and special-tag tail destination.

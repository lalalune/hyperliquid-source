# RE-017 · Replay result cleanup layout

Node #115. The worker call at `0x5a6f9d3` reaches `[0x5b4dae0,0x5b4db5e)`. On the selected normal path, a nonzero outer count at +0x10 starts iteration over a pointer from +0x08 with 56-byte stride. For each row, +0x30 controls the number of calls to `0x5b232a0`; +0x28 supplies the first pointer and each call advances it by 64 bytes. Independently, +0x20 controls the size argument to the release slot, multiplied by 64. A zero +0x30 skips element calls but does not bypass the +0x20 test.

This matches the nested pointer/count positions and strides recorded in the fingerprint serializer. Matching layouts alone leave the worker-side pointer identity and intervening writes unresolved. This packet establishes the cleanup contract for the selected path.

Run the local verifier from the repository root. Static checks cover the exact FDE, contiguous bytes, original direct call and changed-displacement rejection.

The worker stores the three-word record at RSP+0x180 with writes at `0x5a6ea22` and `0x5a6ea2f`. The fingerprint call passes this cell by address in RSI at `0x5a6ed04`, and the selected cleanup call passes the same stack address in RDI at `0x5a6f9cb`. The cleanup subsequently reads +0 and +8 from that cell and scales the former by 56 at `0x5a6f9ed`. Eleven pinned instructions establish shared stack storage and the outer stride. This does not establish unchanged pointee identity across the intervening calls, nor that every path visiting the fingerprint also reaches this cleanup.

### Post-block projection and cleanup decision

Immediately after the adapter call, the worker copies a 24-byte record from stack +0x60 into +0x180. On the later selected R14B=1 path it copies that same stack cell to +0x67: the two stores use +0x88−0x21 and +0x88−0x11. It stages the overlapping 31-byte span starting at +0x60 into a separate result record and clears EBP. The alternate path stages a different 31-byte span and sets BPL to 1. After ABI-conforming normal returns from the intervening calls, the BPL test skips local vector cleanup on the first path and reaches it on the alternate path. This is evidence for a conditional record forwarding and cleanup contract. Slot aliasing and the initial producer's inner-row construction still require separate closure.

### Contrast with the existing nested cleanup

The existing result-sort cleanup at `0x5b4f1c0` also calls `0x5b232a0` and walks the nested elements in 64-byte steps. Its **outer** stride is 64, with nested capacity, pointer and count at +0x28/+0x30/+0x38. The worker cleanup instead uses outer stride 56 and +0x20/+0x28/+0x30. This distinction matters for the proposed producer-to-fingerprint join. A common nested destructor and identical inner stride can hold even when the outer records differ, so they cannot establish the join by themselves. The prior cleanup body is contextual and has been checked byte-for-byte against the capture.

From the repository root, run `python3 research/work-items/RE-017-node115-replay-result-cleanup/verify.py`.

# RE-017 · Replay queue payload and readiness publication

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The [sequence registration packet](../RE-001-node115-transaction-sequence-registration/README.md) identifies a call to queue helper 0x581b0c0. Here the new scope is a separate caller at 0x5a35b8b and the shared helper's selected publication path.

At the selected caller, the 16-byte argument at stack +0x40 contains a zero first word and a second word from RCX. The producer descriptor is the caller's saved base plus 0x80. The producer atomically adds one to descriptor +8 and uses the old value as its index. It compares that index rounded down to a multiple of 32 with the segment's base word at +0x200, and uses the low five bits for the slot. The alternate segment-selection route can follow +0x208 links before joining the store.

The producer writes the two-word input to segment offset 16×slot at 0x581b252. The next instruction is a locked OR of 1 shifted by the slot into segment +0x210. The selected replay probe at 0x581a100 independently tests the same bit position and reads the same two-word slot when that bit is set. This matches the field layout and the producer's store order. It does not prove that the two selected callers have the same live segment pointer or that a specific record reaches the reader. Segment allocation, contention and wake behavior remain open.

Run `python3 research/work-items/RE-017-node115-replay-queue-publish/verify.py` from the repository root to verify the extents, the selected caller and byte windows, and 128 synthetic segment and slot coordinates.

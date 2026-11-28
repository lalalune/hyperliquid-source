# RE-009 — Node #115 quantity-ring row linearization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The ring-to-tree converter in #7496 delegates its compact input buffer to `0x5b79d40`.

The helper reads capacity, buffer, head and length in four consecutive words. For a nonempty valid ring it allocates 24 times the length and normalizes the head by subtracting capacity once when needed. The first copy loop reads from the normalized head through the earlier of the physical end or the logical end. If any rows remain, the second loop starts at physical slot zero and appends them after the first span. Both loops copy 16 bytes and a trailing qword per row.

The old buffer is released with byte size `capacity * 24` on the nonzero-capacity branch after the copies. The result stores the requested row count, new buffer pointer and number of rows actually copied. The zero-length staging path uses pointer value 8, with zero requested count. On the selected valid ring domain the emitted order is the original logical order, before the downstream ordering helper.

Allocation failures, later sort behavior and tree construction are outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-ring-linearization/verify.py` from the repository root for static evidence and synthetic layout checks.

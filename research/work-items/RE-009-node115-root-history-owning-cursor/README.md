# RE-009 · Owning history cursor handoff and exhaustion

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The two selected history row collectors call the same cursor at 0x51e06d0, from 0x5b75046 and 0x5b9b836. This packet describes the selected owning tree descriptor with tag 1 and an accurate remaining count.

For a nonzero count at cursor +0x40 the helper decrements that word before selecting a result. A previously unset front descends from the staged root along child slot zero and initializes the front at the leaf. With a valid front, the helper compares the stored slot with the current node's count. On the in-range path the output holds the current node, level, and slot at +0, +8, and +16. At a leaf the next front retains that node and increments its slot. At an internal node the next front descends from child slot current-slot+1 and follows slot zero to the leaf. The internal key itself is returned first.

When the front slot is exhausted and the count still permits another result, the selected path reads the current node's parent and parent slot before releasing the exhausted node. It uses release size 0x1c8 at level zero and 0x228 for an internal node. The loop continues until the parent slot identifies an unconsumed key. If the count was zero on entry, a separate arm clears the cursor tag, releases the remaining front-to-root chain on the selected active-front case and returns a null node. The next call with the same zero count and cleared tag skips those releases.

The selected advance is therefore consuming. Preserving an unowned node pointer beyond another advance can outlast that node. The collectors project the key and value before advancing again. This is a conditional interpretation of the observed release boundary and valid cursor state. It leaves noncanonical tags, inconsistent metadata and abnormal allocator behavior outside the claim.

Run `python3 research/work-items/RE-009-node115-root-history-owning-cursor/verify.py` from the repository root. The verifier reads the authenticated target, checks its unwind extent and verifies selected transfer and operand bytes.

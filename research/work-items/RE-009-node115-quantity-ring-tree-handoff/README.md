# RE-009 — Node #115 quantity ring-to-tree construction handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [quantities ring-map packet](../RE-009-quantities-ring-map-115/) establishes the upsert's transition trigger and leaves converter `0x516b610` unresolved.

The upsert calls the converter at `0x4dd6331`. The converter copies the four input words to local storage and calls `0x5b79d40`. That helper's entry reads the flat length at +0x18 and computes 24 bytes per row. The converter uses the returned buffer and count. Zero count yields an empty tree descriptor and releases the temporary storage when its capacity is nonzero.

For nonzero counts the converter skips ordering at one row, calls `0x53eea20` for counts 2–20 and uses relocated slot `0x64e5368 -> 0x36e5360` from count 21. The paths converge on an allocation of 0x118 bytes and an iterator descriptor tagged 2 with an end pointer at buffer plus 24 times count. The builder `0x4caff20` receives the iterator and separate tree and count outputs. The converter copies the resulting pointer, height word and count to its caller.

This packet covers conversion staging and output handoff. It leaves the internal flattening copy sequence, ordering callee internals, node construction inside the builder and the companion tree-to-ring path open. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-ring-tree-handoff/verify.py` at the repository root.

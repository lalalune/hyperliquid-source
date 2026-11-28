# RE-009 — Node #115 matched quantity conversion handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. After matched-tree processing, the paired quantity helper enters the conversion gate when the marker is the tree marker and count is below 32 (#7684).

On the qualifying tree path, it takes the descriptor's +8 pointer and +0x10 height, clears +8 and +0x18, and builds a temporary iterator descriptor. It calls `0x3dac770`, which sizes an output allocation from iterator +0x40 using 24 bytes per row and uses pointer 8 for an empty allocation. The caller then builds another iterator descriptor from the retained pointer and drains it through `0x390cf80` until the returned first word is zero. It writes four output descriptor words to the quantity object.

This establishes the conversion handoff for the matched traversal. The separate remove-by-key conversion is described in #7511. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-conversion-handoff/verify.py`.

The verifier binds the retained instruction bytes and relative targets to the pinned ELF and checks corruption detection. The allocation-size and ownership descriptions are static interpretations of the instruction windows, not behavioral or differential tests. The target is not executed.

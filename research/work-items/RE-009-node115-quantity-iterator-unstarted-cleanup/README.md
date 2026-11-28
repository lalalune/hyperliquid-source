# RE-009 — Node #115 unstarted quantity iterator cleanup

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The zero-remaining iterator cleanup in #7770 follows a non-null current node up through its parent chain. This packet covers its null-current-node continuation at `0x51da66c`.

The cleanup has saved the words at state +0x10 and +0x18 in registers before clearing the state tag. If the saved +0x18 word is zero, it sets the cleanup height to zero and enters the parent-chain release at `0x51da474` using the saved +0x10 pointer. Otherwise it follows child zero at +0x118 for that many levels, using a remainder loop and groups of eight, then enters the same release path with height zero.

The evidence concerns the pointer and height handoff on this branch. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-iterator-unstarted-cleanup/verify.py`.

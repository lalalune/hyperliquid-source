# RE-009 — Node #115 quantity remove tree dispatch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The quantity remove entry `0x4ddbf90` selects its tree arm from the first descriptor word and calls `0x51d8900` with the descriptor address plus eight and the incoming key. After the removal helper returns, the caller reloads the count at +0x18. If the descriptor still carries the tree marker `0x8000000000000000` and that count is at most 31, it enters the tree-to-ring conversion. Before building the conversion iterator, it takes the pointer and height from +8 and +0x10 and clears +8 and +0x18.

The removal helper itself is covered in #6217. The later conversion and row handoff are covered in #7511. This packet binds their normal caller, post-call threshold and ownership handoff. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-remove-tree-dispatch/verify.py`.

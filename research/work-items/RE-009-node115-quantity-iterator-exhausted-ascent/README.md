# RE-009 — Node #115 exhausted quantity iterator ascent

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The quantity tree iterator `0x51da3a0` tests its slot against node count at +0x112. When the slot is at or beyond that count, it enters `0x51da584`. The in-range behavior is covered in #7519.

The iterator reads the exhausted node's parent at +0xb0 and edge index at +0x110. Before moving to the parent, it releases the exhausted node through slot `0x64df4a0`, using 280 bytes for height zero and 376 bytes otherwise. It increments height, then compares the saved edge index with the parent count. If the edge is also at or beyond that count, the loop repeats with the parent. Otherwise the parent and edge become the selected position. A null parent branches to the terminal continuation.

This packet covers exhausted-node ascent and release. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-iterator-exhausted-ascent/verify.py`.

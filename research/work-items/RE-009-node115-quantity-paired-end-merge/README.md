# RE-009 — Node #115 quantity paired-end merge

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The small-sort call at `0x4290ac9` enters `0x43b4e60`. The paired-end merge at `0x43b51f1` reads the ordered halves from scratch rather than selecting one half to copy, as in the main ordering merge (#7563).

The merge places a low row and a high row into opposite ends of the output in each pair iteration. At the low end it chooses the left half for equal unsigned keys. At the high end it chooses the right half for equal keys. Each output row copies three qwords, and pointer updates scale by 24 bytes. An odd count leaves one middle output row, which is copied from the half with a remaining row.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-paired-end-merge/verify.py` to verify the instructions and synthetic row fixtures.

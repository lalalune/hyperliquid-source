# RE-009 — Node #115 quantity-tree key runs

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The quantity converter calls the tree builder `0x4caff20` from `0x516b6e0` with ordered rows.

On the ordinary input path the builder reads a 24-byte row as a key qword followed by a 16-byte value. Each additional row with the same key replaces the pending value. When it encounters another key it keeps that key and value as one row of lookahead. At the end of the input it clears the lookahead flag. For a nonfull node, one output entry is written per run: the key goes into the qword array at +0xb8, the last value into the 16-byte array at the node base, and the node count at +0x112 and total entry count each increase by one.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-key-runs/verify.py` to verify the instruction windows and synthetic ordered-row fixtures. The full-node path is outside this packet.

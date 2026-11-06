# RE-017 · Replay callback override membership

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The replay worker calls 0x5a63100 from its null-record and paired callback paths. This packet follows the callback's membership calculation and the boolean forwarded into the operation labeled `update_and_get_overrides`.

The callback calls 0x4f24140 and keeps its result. If input context byte +0x20 is exactly 1 and the returned count at +0x20 is nonzero, it loads the target dword from context +0x21 and the row pointer from the returned object +0x18. It steps the returned data in units of five bytes. A row matches if byte zero equals 1 and its dword at +1 equals the target dword. The first match supplies byte 1. Exhaustion, a zero count, or a different context flag supplies zero.

The callback stores the boolean at stack +0x118 and passes its address in the descriptor at stack +0x210 to 0x4f0fce0. The surrounding operands reference the 24-byte operation label. This establishes an exact input to the next helper without assigning a source-level type to the key or inferring which settings are changed. It assumes a valid result and nonwrapping row-count arithmetic.

Run `python3 research/work-items/RE-017-node115-replay-override-membership/verify.py` from the repository root. It verifies the selected caller edges, extent, operand windows and literal, and compares six synthetic inputs against the inferred membership rule.

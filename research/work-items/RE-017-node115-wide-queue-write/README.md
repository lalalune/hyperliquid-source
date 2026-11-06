# RE-017 · Wide replay queue record publication

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Replay call 0x5a6fe24 sends the stack record at +0x60 to 0x581a2d0, using the descriptor formed at 0x5a6e2a3 from the saved object plus 0x80.

The producer's locked exchange-add reserves an index at descriptor +8. The selected publication window scales the slot by 88. It writes the qword at row +0x50 and five 16-byte lanes at +0x40, +0x30, +0x20, +0x10 and +0, in that order. After the final store it sets the slot bit at segment +0xb10 with a locked OR. The selected reader at 0x58189f0 uses the same stride and readiness offset. This shows field layout and instruction order under valid descriptors. It leaves live pointer identity and concurrent segment advancement open.

Run `python3 research/work-items/RE-017-node115-wide-queue-write/verify.py` from the repository root to verify the authenticated target and operand windows.

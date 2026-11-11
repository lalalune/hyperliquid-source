# RE-017 · Wide queue read and terminal flag

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. In the selected read window of 0x58189f0, the low five index bits select a readiness bit in segment +0xb10. A set bit copies the full 88-byte slot at 88 times that index modulo 32. The read index advances only if the copied first word is at least 0x8000000000000002 under signed comparison.

If the readiness bit is clear, segment bit 33 selects output head 0x8000000000000000 when set and 0x8000000000000001 when clear. This arm does not advance the index. The flag offset and bit match the selected exit-side publication in 0x581be00. The evidence establishes the shared layout, conditional on valid descriptors. Runtime pointer identity and interleaving remain open.

Run `python3 research/work-items/RE-017-node115-wide-queue-read/verify.py` from the repository root to check the authenticated target and operand windows.

At caller 0x5a348b6 the first returned word is saved and negated for an overflow test. The signed-minimum sentinel goes directly to 0x5a349e0. The next sentinel, signed minimum plus one, reaches the preparation slot 0x64e0518 and a second call to the same reader at 0x5a34904. That second call has the same signed-minimum overflow destination. The two sentinel values thus select distinct local paths. This packet leaves later callback effects open.

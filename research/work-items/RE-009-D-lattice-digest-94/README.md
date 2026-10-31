# RE-009-D lattice digest (hl-node #94)

Standalone packet: `tools/lattice_digest.py` derives `lattice-digest.json` from the binary. `verify.py` regenerates it and checks the exact pins. `independent_verify.py` imports nothing from tools/ and checks 101 key VAs byte by byte, reporting PASS, FAIL or INCONCLUSIVE. `tests/test_lattice_digest.py` holds the pins, the seed checks and the tamper tests. See EVIDENCE.md.

## What this does not claim

- It does not prove the hash is BLAKE3 by test vectors. The identification rests on the IV, the 0x400 chunk, the 0x401 compare and ROOT flag 8.
- It does not say what the 16-byte trailers mean. "Two u64 counters" is inference.
- It reports no consumer observed for the digest in either caller's post-digest window (A frees with no read observed; B overwrites the first 32 bytes then frees). This is a bounded negative: a later read of rsp+0x40..0xaf after 0x332d440 / 0x3269ae0 receive the record pointer is possible but not observed, because only the first 0x180 bytes of 0x3269ae0 were read.
- It does not say the writer persists the digest. The writer is never passed it.
- It does not trace the once-init routine (0x576e8b8), platform slot 0x57700c0, or the relocations for GOT slots 0x5770818 and 0x576dfe0.
- It makes no claim about other releases, about source code, or about consensus behaviour.
- It does not reimplement or compare anything (no Rust path).

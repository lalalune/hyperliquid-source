# Evidence

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `0x4d45150–0x4d4523a` (234 bytes), `.eh_frame` FDE VA `0xf18558`
- Coordinate system: ELF virtual addresses; bytes were read-only and no captured code was executed or emulated.
- Independent checks: 16 instruction witnesses and two rejected in-memory mutations at the FDE entry and tag-9 writer.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The fallback passes the two-byte .rodata slice Sz to 0x47c4420. For local tag 9 it writes byte 9, qword 1 at +8 and the payload at +0x10. The input-byte 0xc0 branch writes byte 9 and qword 0 at +8. Other local tags copy 32 bytes.

Reproduce from the repository root with the authenticated artifact and GNU objdump on PATH.

`python3 research/work-items/RE-146-node115-ema-short-c118/verify.py`

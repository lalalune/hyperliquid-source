# RE-121: node115 EMA short c92

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d437a0–0x4d43922` (386 bytes), `.eh_frame` FDE VA `0xf180b8`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 19 instruction witnesses, and two negative controls. Selected instructions show the bounded scan, cursor update, marker write, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected n/u/l/l scan writes qword 0x8000000000000000 to result +0 at 0x4d43885. A separate path calls 0x526da20 with the 18-byte .rodata slice StakeDiscountTiers in RDX and length 18 in ECX. After this call, subtraction of the returned first qword from zero selects the overflow arm only for 0x8000000000000000. That arm writes 0x8000000000000001 followed by the returned second qword. The other arm copies the 24-byte local record.

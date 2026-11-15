# RE-122: node115 EMA short c93

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43930–0x4d43a3c` (268 bytes), `.eh_frame` FDE VA `0xf180e4`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 19 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, marker write, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected byte-0xc0 arm branches to the qword 0x8000000000000000 store. The alternate call to 0x4bf4a20 uses a local result slot at rsp +8 and zero in EDX. When that slot's leading word equals 0x8000000000000000, the function copies the next 32 bytes and writes leading qword 0x8000000000000001. The unequal arm copies seven 16-byte blocks to result +0 through +0x6f. These paths use different result extents.

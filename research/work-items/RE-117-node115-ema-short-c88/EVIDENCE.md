# RE-117: node115 EMA short c88

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43340–0x4d4341c` (220 bytes), FDE VA `0xf17ff0`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, nine instruction witnesses, and two negative controls. The selected instructions show state-byte initialization, cursor/count updates, the marker write, the fallback call, and the return sequence as direct disassembly observations.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d43340` include `0x48a67f2` (`0x48a6300` FDE, call). The marker path writes 0x0209 at 0x4d433ca. The alternate call to 0x4afa940 at 0x4d433e3 is followed by a one-byte value 9 at 0x4d433f7. The two stores use different widths.

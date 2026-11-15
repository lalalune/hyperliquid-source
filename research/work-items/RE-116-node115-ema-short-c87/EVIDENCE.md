# RE-116: node115 EMA short c87

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43240–0x4d43332` (242 bytes), FDE VA `0xf17fb4`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, nine instruction witnesses, and two negative controls. The selected instructions show state-byte initialization, cursor/count updates, a marker write, and the final return sequence as direct disassembly observations.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d43240` include `0x48e294b` (`0x48e2380` FDE, call). The marker path writes 0x0209 at 0x4d432ca. The alternate call at 0x4d432fa is followed by a one-byte value 9 at 0x4d4330d. The two stores use different widths.

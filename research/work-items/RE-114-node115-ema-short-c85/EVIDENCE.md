# RE-114: node115 EMA short c85

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d42fd0–0x4d4312e` (350 bytes), `.eh_frame` file offset `0xf17f48`.
- The packet is a static binary witness only. It does not claim symbol identity, source equivalence, or runtime behavior.

The extent is independently indexed by `tools/fde_extents.py`. The verifier checks the target hash, exact FDE row, seven instruction witnesses, and two negative controls: changing the entry byte or the terminal marker must make the witness set fail.

The selected body shows a bounded scan over the object at `rsi`, updating the cursor at `0x28(%rsi)` and writing either the success marker `0x0200` or a fallback result to the output at `rbx`. Those are descriptions of observed instructions, not inferred source semantics.

# RE-114: node115 EMA short c85

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d42fd0–0x4d4312e` (350 bytes), FDE VA `0xf17f48`.
- The packet is a static binary witness only. It does not claim symbol identity, source equivalence, or runtime behavior.

The extent is independently indexed by `tools/fde_extents.py`. The verifier checks the target hash, exact FDE row, twelve instruction witnesses, and two negative controls: changing the entry byte or the terminal marker must make the witness set fail.

The selected body shows a bounded scan over the object at `rsi`, updating the cursor at `0x28(%rsi)` and writing either the success marker `0x0200` or a fallback result to the output at `rbx`. Those are descriptions of observed instructions, not inferred source semantics.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d42fd0` include `0x5257c81` (`0x5257c40` FDE, call), `0x526953d` (`0x5268f00` FDE, call). The path to the 0x0200 store compares the ASCII bytes n, u, l, l at 0x4d4303c, 0x4d43066, 0x4d43082, and 0x4d4309e. The cursor updates at 0x4d4309a before the final comparison and marker store at 0x4d430a3.

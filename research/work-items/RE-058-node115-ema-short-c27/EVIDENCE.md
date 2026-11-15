# Evidence

The packet records tag/mode classification, branch-separated setup, SIMD `pcmpeqb`/`pmovmskb` equality validation, and the bounded follow-on dispatch. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d39620, 0x4d39ee8)`, length 2248, FDE VA `0xf17088`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d39620` include `0x4dce0bc` (`0x4dcdfc0` FDE, call).

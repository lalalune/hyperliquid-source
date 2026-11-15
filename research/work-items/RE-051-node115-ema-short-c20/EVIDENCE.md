# Evidence

The packet records the tagged branch, indexed-count scaling on both paths, bounded cursor loops, child-transition edges, and terminal result stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch targets, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d389a0, 0x4d38af2)`, length 338, FDE VA `0xf16ee4`

The low-bit tag test at `0x4d389af` selects the alternate path at `0x4d38a60`; the primary path scales the count loaded from `+0x272` by 0x10 and loops from `0x4d389ed`. Both paths can transition through the bounded child pointer at `+0x278`, and the terminal path stores result fields at `+0x08`, `+0x10`, `+0x18`, and `+0x00`.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d389a0` include `0x4dd8777` (`0x4dd8450` FDE, call).

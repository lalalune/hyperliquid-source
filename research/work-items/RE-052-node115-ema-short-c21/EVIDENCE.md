# Evidence

The packet records the indexed count load and 0x20-byte scaling, comparator call, loop transition, bounded child descent, and terminal result stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch targets, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d38b00, 0x4d38c10)`, length 272, `.eh_frame` offset `0xf16f14`

The helper loads the record count from `+0x42a`, scales it by `0x20`, compares a 0x14-byte record through the indirect comparator, increments the record cursor, and descends through child entries at `+0x430` while the external bound remains.

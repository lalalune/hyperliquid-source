# Evidence

- Artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `[0x4d3bbe0, 0x4d3c990)`, 3504 bytes
- `.eh_frame` offset: `0xf172e8`
- Static witnesses cover the normalized length prologue, jump-table dispatch, shared indirect comparator call, sentinel branches, and terminal byte-field comparison.
- Identity controls reject truncated and first-byte-mutated captures.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3bbe0` include `0x4dcc283` (`0x4dcc0a0` FDE, call), `0x537608b` (`0x5375fa0` FDE, call), `0x53762eb` (`0x5375fa0` FDE, call), `0x537871d` (`0x5378220` FDE, call).

# RE-008: node #115 EMA narrow-chain helper evidence

- FDE `[0x4d2fe70, 0x4d30055)`, 485 bytes, FDE VA `0xf16394`.
- Body SHA-256: `3f4eba69a0feaf47082c0ce25eeefaba8c2307702035eb75df7d0278e819347`.
- The helper follows a narrow linked-node chain using selector `+0x62` and link `+0x68`, stages a selected record through a local update call, replaces a descriptor slot, and relinks descendants.
- It records the empty-root edge and final result writes at `+0x00`, `+0x08`, `+0x10`, and `+0x18`.
- Witnesses and mutation controls are local byte checks only. They do not establish source-level types, ownership, or runtime equivalence.

The existing sorted-set packet binds a caller to the order-book removal path. This packet adds descendant-link and return-store witnesses inside the helper. [Related packet](../RE-006-node115-sorted-set-read-side/README.md) Reviewed static incoming edges to `0x4d2fe70` include `0x51d50a8` (`0x51d5010` FDE, call), `0x51d6ac8` (`0x51d6a30` FDE, call), `0x51d7818` (`0x51d7780` FDE, call), `0x51d8878` (`0x51d87e0` FDE, call).

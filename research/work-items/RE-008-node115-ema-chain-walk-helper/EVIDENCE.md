# RE-008: node #115 EMA chain-walk helper evidence

- FDE `[0x4d2f8c0, 0x4d2fb8d)`, 717 bytes, FDE VA `0xf16318`.
- Body SHA-256: `36153780be9820c9990cfe77d27277f3ad90e14ccdf7f5c87bcba1a291c7a26e`.
- The helper reads a root, follows `+0x170` links using the node selector at `+0x16a`, and walks both scalar and unrolled paths.
- It stages a selected record, calls the local chain-update helper, writes the selected record back, updates descriptor fields at `+0xe4`/`+0xec`, relinks descendants, and writes result fields at `+0x00`, `+0x10`, `+0x20`, `+0x28`, and `+0x30`.
- Witnesses and mutation controls are local byte checks only. They do not establish source-level types, ownership, or runtime equivalence.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d2f8c0` include `0x5151018` (`0x5150d10` FDE, call), `0x51515a8` (`0x51512a0` FDE, call).

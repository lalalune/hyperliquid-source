# RE-008: node #115 EMA deep-branch helper evidence

- FDE `[0x4d2e480, 0x4d2ec38)`, 1976 bytes, FDE VA `0xf162c8`.
- Body SHA-256: `306bb559ffec4bfcc550911d7a30703e628495aacc4690168f9e906f152e3c8d`.
- The helper stages a descriptor record from indexed fields at `+0x60`/`+0x70`, performs two indirect copies, decrements the root count at `+0x13e`, and preserves the selected pointer at `+0x60`.
- It records capacity and empty-root guards, selected-child propagation through `+0x138`, descriptor relinking and count updates at `+0x13c`/`+0x13e`, and final result fields through `+0x00`, `+0x10`, `+0x18`, `+0x20`, and `+0x30`.
- Witnesses and mutation controls are local byte checks only. They do not establish source-level types, ownership, or runtime equivalence.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d2e480` include `0x4d37d09` (`0x4d37be0` FDE, call), `0x4d37dfd` (`0x4d37be0` FDE, call).

# RE-008: node #115 EMA branch2-helper evidence

- FDE `[0x4d2ad00, 0x4d2b46c)`, 1900 bytes, FDE VA `0xf16138`.
- Body SHA-256: `9420057981f340d870d8b1249d657c55828fdc44ce0eccb8ff11a55f04ef57cb`.
- Loads root and count at `+0x62`, stages indexed fields at `+0x64`/`+0x71`, performs indirect copy calls, decrements/stores the count, and reloads the selected entry.
- Capacity and empty-root guards are recorded with direct edges; a short descendant branch is retained as an instruction witness. Source-level types and ownership remain unresolved.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d2ad00` include `0x4d35eee` (`0x4d35df0` FDE, call), `0x4d35fdd` (`0x4d35df0` FDE, call).

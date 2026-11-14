# RE-008: node #115 EMA branch2-helper evidence

- FDE `[0x4d2ad00, 0x4d2b46c)`, 1900 bytes, entry offset `0xf16138`.
- Body SHA-256: `9420057981f340d870d8b1249d657c55828fdc44ce0eccb8ff11a55f04ef57cb`.
- Loads root and count at `+0x62`, stages indexed fields at `+0x64`/`+0x71`, performs indirect copy calls, decrements/stores the count, and reloads the selected entry.
- Capacity and empty-root guards are recorded with direct edges; a short descendant branch is retained as an instruction witness. Source-level types and ownership remain unresolved.

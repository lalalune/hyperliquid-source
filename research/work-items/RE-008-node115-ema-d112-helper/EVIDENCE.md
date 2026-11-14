# RE-008: node #115 EMA d112-helper evidence

- FDE `[0x4d2da90, 0x4d2e268)`, 2008 bytes, FDE VA `0xf16228`.
- Body SHA-256: `f9e140eefe24a984da97d1138de1b81c09a4f856b9f70f58864f055ff2f887bd`.
- Loads root and count at `+0x112`, stages indexed fields at `+0x08`/`+0x18`, performs indirect copy calls, decrements/stores the count, and reloads the selected entry.
- Capacity guard is recorded with a direct edge; short empty/descendant branches remain instruction witnesses. Source-level types and ownership remain unresolved.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d2da90` include `0x4d36543` (`0x4d36420` FDE, call), `0x4d3662d` (`0x4d36420` FDE, call).

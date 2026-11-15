# RE-008: node #115 EMA branch-helper evidence

- FDE `[0x4d26bd0, 0x4d26fbd)`, 1005 bytes, FDE VA `0x12f2414`.
- Body SHA-256: `b6c4b10737cc18df141c18e1911a768ebe99727590850abedcf033ecbaa1f0de`.
- Entry loads root pointer and 16-bit count at `+0x4ae`, stages indexed record fields at `+0x3d0`/`+0x3e0`, and calls the indirect copy slot.
- The helper decrements/stores the count, reloads the selected entry at `+0x08`, and preserves the staged record across explicit capacity, empty-root, and descendant-count branches.
- Descendant descriptors capture root, index, child pointer, and next index before the internal recursive call; the packet does not assign source-level types or ownership.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d26bd0` include `0x4d36e3f` (`0x4d36d10` FDE, call), `0x4d3700c` (`0x4d36d10` FDE, call).

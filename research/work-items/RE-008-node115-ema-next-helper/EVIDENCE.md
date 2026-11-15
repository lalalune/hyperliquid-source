# RE-008: node #115 EMA next-helper evidence

- FDE `[0x4d27b00, 0x4d28626)`, 2854 bytes, FDE VA `0x12f24bc`.
- Body SHA-256: `99637f617f3163972511a163c2d961ba4329d55d0c395e6ab103eccb976f180c`.
- Loads root and count at `+0x79a`, stages an indexed `0xa8` record from `+0x60`, performs tail copying, decrements/stores count, and reloads the selected entry.
- Capacity, empty-root, descendant-count, and index-order guards are recorded with direct edge witnesses; source-level ownership and types remain unresolved.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d27b00` include `0x4d30545` (`0x4d30420` FDE, call), `0x4d3064e` (`0x4d30420` FDE, call).

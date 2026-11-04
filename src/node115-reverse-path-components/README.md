# Node #115 Unix reverse path components

Dependency-free `no_std` Rust projection of the fresh Unix component iterator
used by captured node115 output preparation. `Reverse::new(&[u8])` accepts byte
paths; `next_back()` yields Root/Current/Parent/borrowed Normal components, and
`remaining()` returns the unconsumed byte view without mutating the iterator.
Interior dot segments and repeated separators are skipped at the appropriate
edges; initial relative `.` is preserved, and `..` is never resolved away.
Backslash and invalid UTF-8/NUL bytes remain ordinary Unix component bytes.
No filesystem lookup, Unicode conversion or path-security policy is performed.

Target SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
The safe state machine covers only the actual fresh constructor and states
reachable by reverse iteration, not arbitrary raw iterator memory, mixed
forward calls, Windows prefixes or the original Rust ABI. See the RE-012
reverse-path-components-115 evidence packet for exact extents and qualifications.

```
cargo +1.95.0 build --locked --offline --manifest-path src/node115-reverse-path-components/Cargo.toml
python3 -B research/work-items/RE-012-reverse-path-components-115/verify.py
python3 -B research/work-items/RE-012-reverse-path-components-115/qualify.py work/path-fresh /absolute/path/to/rustc-1.95.0
```

Only our compiled rlib and probe execute. The probe links the real no_std
library with --extern and compares pure std::path parsing without OS I/O.

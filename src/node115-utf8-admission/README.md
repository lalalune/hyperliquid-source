# Node #115 logical UTF-8 admission

Independently authored `no_std`, dependency-free Rust projection of the complete
validator at ELF VA `0x16815e0..0x16817d7`, authenticated node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
New API `validate(&[u8]) -> Result<(), Invalid>` exposes only valid-prefix
length and optional bad-sequence length. It does not reproduce native Result
layout, output pointers or inactive bytes. The source does not call a UTF-8
library; the separate qualification uses CPython's codec as an independent
reference. This common UTF-8 primitive is not claimed as private node logic.

```
cargo +1.95.0 build --offline --locked --manifest-path src/node115-utf8-admission/Cargo.toml
python3 -B research/work-items/RE-012-utf8-admission-115/verify.py
python3 -B research/work-items/RE-012-utf8-admission-115/qualify.py work/utf8-fresh /absolute/path/to/rustc-1.95.0
```

`src/probe.rs` is a synthetic hexadecimal-line qualification adapter and uses
std; it is not the library's API or a recovered node protocol. Only our newly
compiled code is executed. The retained evidence packet explains the static
mapping, oracle timing, fixtures, controls, builds and remaining uncertainty.

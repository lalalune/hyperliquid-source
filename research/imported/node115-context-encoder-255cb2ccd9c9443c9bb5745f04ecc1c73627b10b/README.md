# Node115 Ctx successful-wire profile

Independent std-only Rust for all thirteen Ctx values, in map or sequence mode.
Target SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The evidence, exact raw timestamp profile, static derivation, controls and limits
are in research/work-items/RE-009-ctx-encoder-115/README.md. No source-language
layout, allocator/panic behavior, runtime differential result or Linux machine
code identity is claimed. The safe public API is independently selected; its
validation error is not a recovered native Result variant.

Run cargo test --offline --locked --manifest-path src/node115-context-encoder/Cargo.toml.
The manifest/lockfile are an isolated real component build, not a recovered root
Cargo workspace. There are no external crate dependencies. All component gates
remain false.

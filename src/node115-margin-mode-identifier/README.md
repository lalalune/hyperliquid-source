# Node #115 margin-mode identifier reader

This independently authored Rust value model follows the five RE-007 Content-pair reader bodies in `research/work-items/RE-007-margin-mode-identifier-115`, target #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It maps the observed U8/U64 indices and exact names `normal`, `noCross`, and `strictIsolated` to variants 0..2; byte arms use lossy UTF-8 on the recorded visitor path; the paired value is preserved byte-for-byte on success. Error outcomes and the selected drop/free/helper event order are represented semantically, without native pointers or result ABI bytes.

The three copy families carry different observed variant-pool coordinates. The two 873-byte Result-form bodies and three 1,002-byte tagged-form bodies are semantically represented through their common decision relation; this crate does not encode either native result layout. Logical `Identifier` cases abstract the observed Content payload layouts; `capacity` controls the selected owned-buffer free event.

Source names and Rust Content types remain interpretations. Error constructors, visitors, allocator helpers, unwind paths, caller semantics, native ABI, input memory validity, and whole-component equivalence are not reconstructed. The target and its instructions are never run or emulated by this crate.

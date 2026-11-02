# Post-delegate JSON-related tail admission

The 440-byte owner at ELF VA `[0x15ba010,0x15ba1c8)` delegates first, then scans forward from the returned cursor. This module implements only that established post-delegate policy. It does not parse a response or trim before parsing.

`finish_tail(output_word, input, cursor)` bypasses scanning for raw word `0x8000000000000001`. Otherwise it admits exactly bytes 09/0a/0d/20, increments the cursor only for admitted bytes, and reports local code 0x16 at the first other byte. A cursor at or beyond length follows the observed no-scan exit; this is not proof that an oversized cursor is reachable. Form feed 0x0c, vertical tab and high bytes are excluded. The unsigned byte bound before the target BT instruction prevents high-byte aliases.

The new `TailResult` is a safe abstract interface, not the original 104-byte result layout. Delegate semantics, error construction, cleanup/allocation helpers, full caller behavior and reachable cursor states remain unresolved.

## Build and validate

This independently authored safe `no_std` module has no dependencies, build scripts, Cargo workspace or lockfile. It is built directly with research rustc 1.94.1, edition 2021, warnings denied and overflow checks on. The compiler pin is not a recovered full-node build recipe.

```sh
python3 -B research/work-items/RE-012-json-tail-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-json-tail-new --controls
```

Use a new output directory. The runner authenticates node #94 and rechecks the [existing static evidence](../../research/work-items/RE-001-json-trailing-admission-94/README.md), then compares 65,915 cases against three own Rust builds and detects 6 compiled semantic mutants. No original machine-code equivalence is claimed. See the [implementation packet](../../research/work-items/RE-012-json-tail-rust-94/README.md) for evidence, actual results and limits.

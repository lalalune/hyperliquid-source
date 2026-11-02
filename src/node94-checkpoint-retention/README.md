# Selected checkpoint row retention

The 595-byte FDE-described owner at ELF VA `[0x33084a0,0x33086f3)` copies selected 32-byte rows. A nonzero marker-helper AL keeps a row unconditionally, irrespective of height bounds. Otherwise a height below lower requests an opaque diagnostic. Conditional on that helper returning normally, keep iff `lower <= height < upper && height <= cap`, all unsigned.

`decide` recovers that selected keep/diagnostic policy. `height` reads the observed little-endian word at row+0x18. `retained_row` returns a kept 32-byte row unchanged, preserving all opaque bytes. These interfaces and `Option`/`Decision` types are new safe Rust, not the original iterator/ABI or an allocation/ownership proof.

A nonzero marker is not permission to delete a file. Filesystem marker determination, the diagnostic's effects/nonreturn paths, allocation, iterator ownership, callers and the complete checkpoint lifecycle remain excluded. The marker result is supplied as a raw byte; no filesystem/helper callback runs.

## Build and validate

This independently authored safe `no_std` module has no dependencies, build scripts, Cargo workspace or lockfile. It is built directly with research rustc 1.94.1, edition 2021, warnings denied and overflow checks on. The compiler pin is not a recovered full-node build recipe.

```sh
python3 -B research/work-items/RE-001-checkpoint-retention-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-checkpoint-retention-new --controls
```

Use a new output directory. The runner authenticates node #94 and rechecks the [existing static evidence](../../research/work-items/RE-001-checkpoint-retention-94/README.md), then compares 12,304 cases against three own Rust builds and detects 6 compiled semantic mutants. No original machine-code equivalence is claimed. See the [implementation packet](../../research/work-items/RE-001-checkpoint-retention-rust-94/README.md) for evidence, actual results and limits.

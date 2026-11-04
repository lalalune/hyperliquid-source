# Node115 varint size-counter state

Standalone independently authored no_std u32/u64 size accounting qualified by
five node115 physical ABI paths. The marker increment commits before checking
remaining payload. Err preserves the observed pre-helper counter state; it does
not reproduce original panic/enum ABI, object layouts or exception behavior.

Direct rustc1.94.1 builds, edition2021; no dependencies, Cargo graph or lockfile.
The scalar contract reuses project-authored MIT reasoning from retired Git
history, with fresh115-specific input/layout/return qualification and frozen
expectations. No retired implementation is kept as a second active target.
See research/work-items/RE-005-varint-size-state-rust-115 for evidence and commands.

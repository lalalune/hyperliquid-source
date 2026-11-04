# Node115 gossip metadata gate

Standalone dependency-free no_std Rust research API. Reuses the project's MIT
scalar policy at5491d673; fresh #115 native expectations were frozen atcfa74eaf
before this component was authored. Direct rustc1.94.1/edition2021 is an explicit
research build, not a recovered original compiler, Cargo graph or object ABI.
See research/work-items/RE-014-gossip-reload-115. No clock/filesystem/parser,
concurrency, whole-function equivalence or full component gate is implemented.

# node94-db-dir-guard

The baseline constructor packet establishes a checkpoint substring guard but leaves the vector candidate checks unmodeled and has no Rust implementation. This adds a safe byte-slice predicate and statically specializes helper 0x158ef30 to the captured nine-byte heckpoint verifier. Its three dword comparisons cover [0,4), [4,8) and [5,9); together with the candidate c/t mask they establish the ten-byte needle. Every failed candidate clears exactly one mask bit.

Build directly with rustc 1.94.1, edition 2021. Safe `no_std`, no external dependencies or root Cargo workspace. The evidence packet `research/work-items/RE-001-db-dir-guard-rust-94/` retains the complete commands, target identity and comparison scope.

Outer-loop coverage is exhaustively established only for lengths 0..512, with additional finite corpus lengths through 1,024. The new byte-slice predicate is defined for all supplied slices, but all-usize target equivalence is not claimed. Valid regions, captured descriptor transfers and ordinary execution are premises. Filesystem/path normalization, native vector memory access/faults, singleton registry, ownership, panic/abort effects and original ABI remain excluded.

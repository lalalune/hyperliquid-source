# Node115 checkpoint lifecycle plan

Independent `no_std` plan for the selected checkpoint vs zero lifecycle routes.
Nonzero mode performs the source copy, optionally copies `/checkpoint` when its
path predicate is false, optionally processes `/lt_hashes.json`, then reaches the
common publication boundary. Zero mode performs one source copy and skips the
checkpoint-specific work.

Command spawning, filesystem predicates, helper effects, durability, rollback
and the 48-byte publication object remain out of scope.

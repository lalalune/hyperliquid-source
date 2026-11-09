# Node115 checkpoint lifecycle plan

Independent `no_std` plan for the selected checkpoint vs zero lifecycle routes.
Nonzero mode performs the source copy, optionally copies `/checkpoint` when its
path predicate is false, optionally processes `/lt_hashes.json`, then reaches the
common publication boundary. Zero mode performs one source copy and skips the
checkpoint-specific work.

Command spawning, filesystem predicates, helper effects, durability, rollback
and the 48-byte publication object remain out of scope.

Target identity: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Target-grounded evidence: `research/work-items/RE-009-node115-checkpoint-lifecycle/README.md`.

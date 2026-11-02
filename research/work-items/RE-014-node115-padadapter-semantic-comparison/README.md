# Node #115 PadAdapter callback trace

The active subject is node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The selected 630-byte FDE is `0x1686bd0..0x1686e46`, body SHA-256
`fc968173616031f08d0a0e77dedca4e6cc4b81ddd1f7cb57e74b10cfae20cb2d`.

`node115.llvm.asm` preserves the full disassembly. The tests bind the full target,
selected FDE, field/branch sites and the frozen `VECTORS.json` callback traces.
The earlier cross-release subject and its disassembly are retired to Git history.
The vector corpus and #115 instruction bytes are unchanged.

The model splits immutable input at LF, requests indentation when the current
state requires it, and preserves callback failure ordering. It requires valid
non-overlapping input, callback metadata and state; callbacks must return
normally and preserve callee-saved registers. Callback state mutation is modeled
only at the explicit boundary. No aliasing, unwind, allocator, nominal type,
original callback identity or source-build equivalence is claimed.

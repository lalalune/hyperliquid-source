# RE-001: node #115 TLS context output publication

- Target: Linux x86-64 `hl-node` #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: what concrete output relation is visible at the end of the
  `0x5ce01f0` helper reached by the TLS-context transform?

The selected body reads the input tag byte at `rsi+0x8`, and its non-fast
path stages fields before the transform. On the selected publication path at
`0x5ce06a0`, it stores the computed pointer in destination `rbx+0x8`, writes
the observed tag constant `3` at `rbx`, returns `rbx`, and follows the native
epilogue. This is an observation about bytes and register flow, not a source
enum name or runtime semantic claim.

`verify.py` authenticates the full target and checks three exact windows in the
helper FDE. No captured code was executed or emulated; other exits and the
meaning of tag `3` remain unresolved.


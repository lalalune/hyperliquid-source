# RE-001: node #115 TLS context transform boundary

- Target: Linux x86-64 `hl-node` #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: what bounded transform edge follows the helper target resolved in
  the preceding TLS-context packet?

The body at `0x5cf9600` branches on its input tag at `rsi+0xe4`. On the
non-fast branch it stages the source fields into a scratch record, calls
`0x5ce01f0` with destination `rsp+0x400` and source `rsp+0x70`, then reads the
result pair from `rsp+0x400/+0x408`. The fast branch instead reads the existing
pair at `rsi+0x8`. This records a concrete branch/call/data-flow boundary, not
a recovered type or ABI.

`verify.py` authenticates the target and checks five exact windows against the
two native FDEs. No captured code was executed or emulated; deeper helper
semantics and runtime reachability remain unresolved.


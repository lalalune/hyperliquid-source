# Node #115 MessagePack numeric variant identifier

This independent Rust model follows the five numeric marker-dispatch copies in `research/work-items/RE-010-action-msgpack-number-identifier-115`, target #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The packet binds the five dispatcher bodies, shared marker arms, integer range tables, visitor outcomes and EOF branches to selected target bytes.

The API covers FixPos/FixNeg, unsigned and signed integer widths, bool, nil, f32/f64, and non-scalar marker pass-through. It returns variant indices for each copy's observed bound (79/92/16/114/18), unexpected-type payloads, out-of-range unsigned values, static EOF identity, and consumed payload length. The Rust test reads the packet's 8,579 previously recorded expected outcomes; it does not invoke the captured-instruction evaluator.

Limits: error formatter output is not reconstructed; EOF identities are static packet addresses, not ABI values; named enums for four sibling copies, full caller deserializers, non-scalar downstream handling and whole-component equivalence remain outside this module. Neither captured binaries nor instruction streams are executed or emulated here.

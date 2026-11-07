# Node #115 wide-byte selection leaf

This dependency-free `no_std` Rust crate implements the bounded register and
two-slot transformation observed in `research/work-items/RE-001-node115-wide-byte-select`.
The target is Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`apply` accepts the depth, the two already-selected 32-byte little-endian
slots and the incoming RAX value. For depth below two it preserves depth and
the slots, changes only AL to `0x2c`, and returns the resulting RAX. Otherwise
it treats the complete 256-bit index as unsigned, selects byte `31 - index`
from the preceding slot for indices 0 through 31 (zero for all other values),
zero-extends that byte into the preceding slot, decrements depth, and returns
RAX zero.

The operation is isolated from its unresolved consumers. The crate does not
assign a source-language type or module owner, recover the function's native
ABI or dispatch path, identify an opcode/API, or model invalid pointers and
the red-zone scratch. Inputs must correspond to the two native slots and be
valid, non-overlapping memory. No captured code is executed or emulated.

## Evidence and reproduction

The packet contains the authenticated complete 137-byte function body,
strictly decoded instruction walk, 50 instruction-grounded relation vectors,
and independent input/FDE/corruption checks. Run its static verifier from the
repository root:

```sh
python3 research/work-items/RE-001-node115-wide-byte-select/verify.py
```

Run this crate's tests with Rust 1.95.0:

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-wide-byte-select/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-wide-byte-select/Cargo.toml --all-targets -- -D warnings
```

The code tests all 32 byte positions, wide and out-of-range indices,
underflow preservation, zero extension, and the packet's frozen 50 vectors.
These establish the bounded projection only; they do not establish call-site
compatibility, source identity, compiled-byte equivalence or component
completion.

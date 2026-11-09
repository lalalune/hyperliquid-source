# Node 115 checked 32-byte read projection

This small `no_std` crate models the bounded state and output behavior of the
Node 115 leaf at `0x5821430`, using the authenticated static packet
[`RE-001-node115-checked-read32`](../../research/work-items/RE-001-node115-checked-read32/README.md).
The packet binds the complete 115-byte FDE, decodes all 37 instructions and
records the exact branch and memory-write order. Target identity is the Linux
x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The projection captures the mode-1 counter addition and limit check, including
the committed increment when the limit is exceeded; the short-input result and
missing-byte count; and the successful 32-byte copy and cursor advance. It
represents only fields observed to be written by this leaf. The model does not
assign a source name or protocol meaning, implement a surrounding decoder, or
claim ABI compatibility, whole-node equivalence, or component completion.

The safe API receives a fixed 32-byte readable window and assumes valid,
nonoverlapping target memory as specified by the packet. Short and error paths
do not inspect that window. No captured executable was run or emulated.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```

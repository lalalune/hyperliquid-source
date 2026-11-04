# Node115 signed scalar

This dependency-free `no_std` component reconstructs the logical value, error
and input-cursor relation of Node115 readers `0x2935ae0..0x2935c45` and
`0x5659e00..0x5659f65`. Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
See [the RE-005 evidence](../../research/work-items/RE-005-node115-signed-scalar/README.md).

`Cursor::read_signed(endian)` reads one value. Zero means little endian;
every nonzero endian byte means big endian. Bytes 0..250 are inline values;
251/252/253 select 2/4/8 payload bytes. Nonminimal encodings are accepted.
The result uses inverse zigzag over the complete unsigned 64-bit payload.

The native fast/short-path distinction is observable. With at least nine
input bytes, an unsupported marker leaves the cursor unchanged and reports
expected diagnostic 8. With fewer than nine bytes, the marker is consumed
first and the expected diagnostic is 9. Marker 254 reports actual diagnostic
10; marker 255 reports 12. A short payload leaves its available bytes unread
and reports the additional byte count. Empty input remains empty.

The API expresses these observations as safe Rust values. It does not
reproduce the original result union's padding, allocation, calling convention,
caller budget/count policy, aggregate wire schema or whole-node behavior.
The three observed call sites pass endian zero; nonzero behavior is established
from the reader instructions, not from an observed big-endian caller.

Build and test with Rust 1.95.0, without downloads:

```sh
cargo test --offline --locked --manifest-path src/node115-signed-scalar/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-signed-scalar/Cargo.toml
```

The six tests exercise target-grounded value/error/cursor expectations. They
are not executions of the captured node. Native differential execution and
original machine-code identity remain unproved.

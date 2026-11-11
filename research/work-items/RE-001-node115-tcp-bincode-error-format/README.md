# Selected TCP bincode error formatting and ownership

Partial HL115-081, node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The prior [typed-result boundary](../RE-001-node115-tcp-typed-result-boundary/README.md) / [#3339](https://github.com/lalalune/hyperliquid-source/pull/3339) identifies the conversion and frame-release call sites but leaves the formatter and returned owner opaque. This closes four selected decoded-error variants under the ordinary non-alternate formatting path and cached backtrace state 1. It does not claim complete decoder, transport or error-variant coverage.

## From decoded input to owned message

The outer reader `0x2b79e30` calls decoder `0x2700010`. A tag other than 0x12 follows `0x2b79feb -> 0x2b7a0b0`, which calls `0x2b41590` with the format bytecode at 0x444d6d. Its first byte 0x16 introduces the 22-byte literal `TcpRead::bincode err: `, followed by default argument bytecode. `0x1609a70` connects that argument to the decoder-error formatter `0x16087a0`. The actual formatting engine's selected default flags are `0x60000020`; its ordinary Debug-struct path emits ` { `, `: `, `, ` and ` }` around fields. The String sink vtable +0x18 resolves to 0x141e8f0: after a capacity check and any successful growth it copies the supplied bytes to pointer+length, increments length and returns zero. Successful growth and non-alternate formatting are premises. The modeled 24-byte raw input is only the selected prefix of a larger decoded enum; inactive fields are not modeled.

| Decoder tag | Selected input | Materialized suffix |
| --- | --- | --- |
| 0 | unsigned qword at +8 | `UnexpectedEnd { additional: N }` |
| 1 | no selected field | `InvalidBytesLength` |
| 2 | no selected field | `LimitExceeded` |
| 3 | type-tag bytes at +1 and +2 | `InvalidIntegerType { expected: E, found: F }` |

The tag table at 0x46a86c binds each arm. Tag 0 uses vtable slot `0x64031e0 -> 0x1607fc0`: its ordinary unsigned decimal path, the pair-digit table and the `0x167e9d0 -> 0x1686260` default sign/padding path supply decimal digits without a plus or padding. Tag 3 uses the direct and indirect type-tag formatters. Their shared 12 pointer/length entries are `U8`, `U16`, `U32`, `U64`, `U128`, `Usize`, `I8`, `I16`, `I32`, `I64`, `I128`, `Isize`. The source accepts only these valid tags; unsupported inputs stop at a source boundary rather than inventing native behavior.

On the selected even argument path `0x141e3a0` immediately materializes an owned string, rather than storing a deferred reference to the decoded error. `0x5c8afb0` with cache byte at 0x6500059 equal to 1 writes state word 1; the remaining inactive state bytes are not modeled or claimed zero. `0x2a020b0` allocates an 80-byte owner containing that state and the string descriptor at +0x38. The typed-result wrapper returns this owner, and the outer reader sets output tag 1 and releases the input frame after conversion on its normal path. The error message remains owned after the frame release. The selected destructor `0x2a01a40` skips backtrace cleanup for state 1, frees the string allocation when its capacity is nonzero, then frees the 80-byte owner. The Rust source models the logical owned message and release order; its `string_len` is not asserted to be the native allocation capacity.

Valid already-decoded values, normal writer/allocation returns, no interfering writes and the stated formatter/cache paths are premises. Other decoder tags, alternate formatting, native pointer/allocator details, dynamic formatter failures, unwind and downstream network behavior remain open. The prefix and message are local owned error text, not a claim of exact wire bytes.

## Validation

`python3 research/work-items/RE-001-node115-tcp-bincode-error-format/verify.py` authenticates the target and checks 19 selected windows (6,126 bytes / 1,590 instructions), the tag table, all 12 integer name pointers and lengths, format bytecode, decimal data and 62 semantic corruption controls. It reads captured instructions as bytes, without execution or emulation. `cargo test --manifest-path src/node115-tcp-bincode-error/Cargo.toml` (also `--release`) covers raw tag and field offsets, literal messages, decimal boundaries including u64::MAX, all 144 integer-name pairs, unsupported boundaries, and the owned-message lifetime event. Formatter/allocator identity is not claimed as a compiled-native equivalence.

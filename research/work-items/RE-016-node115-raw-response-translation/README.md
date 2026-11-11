# Raw-response translation after decoding

Partial high-priority backlog rank097; RE-016 remains incomplete. This closes a bounded method-specific continuation: trailing-byte acceptance, copying a decoded32-byte success, native error-category mapping, and selected error-data JSON serialization. It does not parse JSON or submit transactions.

## Target and evidence

Original node115 ELF, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105896032 bytes. `records.json` binds8 original instruction windows, 3418 bytes /813 instructions, actual call edges, two relative jump tables, the200-byte decimal-pair table, and the finite-float relocation. `verify.py` first authenticates the digest and bytes; its38 semantic corruption controls then bypass those hash checks and must be rejected by the instruction/edge/data assertions. No captured target instructions were executed or emulated.

## Concrete contract

The input is an already-decoded `Success([u8;32])` or error `{code:i32,message,data}`, plus the original input and a valid reader cursor. This is a stated prerequisite, not a callback pretending to implement the parser. Native `0x1700bd0` calls decoder `0x1707010`; that decoder remains open here. The related generic codec in prior #2127 is not asserted to be identical to this decoder.

1. `0x1700c32` checks the decoder-failure sentinel `0x8000000000000001`. An existing decoder failure bypasses trailing-byte checking. Otherwise, the cursor consumes only bytes9,10,13,32 (mask `0x100002600` at `0x1700c9f`). It leaves the first other byte unconsumed and reaches `0x16ffc80` with raw error code22. The source returns `BeforeTrailingError22` at that boundary; it does not fabricate the error position or cleanup. Cursor greater than input length is a source-domain guard, **not a reconstructed native error**; valid cursors are a premise.
2. The real caller `0x174ab57` invokes that wrapper. On decoded success, `0x174adea..0x174ae16` copies exactly32 payload bytes and writes native output tag3. On decoded error, `0x174aecb..0x174af02` passes the code, message descriptor and optional72-byte value to `0x17023b0`; its56-byte result is copied to the same output area. Source strings are logical owned bytes; native descriptor identity, capacity, allocation and later destruction are not modeled.
3. `0x17023b0` distinguishes absent data (word `0x8000000000000005`) from a present value. Absent data skips serialization and yields tag2. Present data reaches `0x173ea10`, then the recursive writer `0x173edc0`, and successful serialization yields tag1. It preserves the original code and message. An inactive native length word on the absent branch is **not** claimed to be zero.

| Code | Raw category |
| --- | --- |
| -32700 | 0 |
| -32007 | 1 |
| -32600 | 2 |
| -32601 | 3 |
| -32602 | 5 |
| -32603 | 6 |
| Every other i32 | 7 |

The four consecutive codes use relative table `0x47e0ec`; the two exceptional comparisons are explicit instructions. The source retains raw categories without inventing semantic enum names.

4. `0x173edc0` selects the value arm using the negative-word tag (or arm5 for a nonnegative word). Selected reconstruction covers literal `null`, booleans, signed/unsigned64-bit decimal, nonfinite floats serialized as `null`, and recursive arrays of supported values. Arrays use72-byte element stride and comma/bracket bytes. Signed decimal is inlined; unsigned decimal calls `0x1741580`; both are checked against the actual10000-group/pair-table logic. The source independently uses division by10, tested against standard decimal formatting, including i64::MIN and u64::MAX. String quoting `0x173d560`, finite float formatting `0x5d0e4c0`, and the object arm stop explicitly; already-written enclosing-array prefixes remain visible at a stop. The object stop is before entering the whole unsupported arm, not a claim about its internal helper boundary.

`0x173ea10` initializes a128-byte output buffer and calls the writer, then produces the pointer/length pair on successful allocation/shrink. Native growth, allocation failure, destruction `0x17044a0`, and raw response buffer cleanup remain prerequisites or exclusions. Rust Vec allocation is a source implementation choice, not a native allocator reconstruction. Selected serialized values always produce nonempty output; absent and JSON `null` remain observably different.

## Prior work and remaining scope

- [#2127](https://github.com/lalalune/hyperliquid-source/pull/2127) owns related JsonRpcResult constructor/alternate-codec,32-byte value and nested error fields. No claim here that generic codec work is new or that its decoder equals `0x1707010`.
- [#2161](https://github.com/lalalune/hyperliquid-source/pull/2161) owns raw forwarding transport/failure-path context. Transport, malformed-response construction and its async state machine remain excluded.
- [#4483](https://github.com/lalalune/hyperliquid-source/pull/4483) owns raw input hex behavior; this contribution concerns the postdecoder response continuation.

Remaining rank097 scope includes the actual response decoder, every data-value arm, outbound envelope encoding, transport behavior, native memory/error cleanup and a full caller-to-wire fixture. This independent fixture consumes explicit decoded data and proves the bounded output relation only. Shared supporting addresses are credited; they are not represented as untouched work.

## Reproduce and validation

From repository root:

```
cargo +1.95.0 test --offline --manifest-path src/node115-raw-response-translation/Cargo.toml
cargo +1.95.0 test --release --offline --manifest-path src/node115-raw-response-translation/Cargo.toml
cargo +1.95.0 fmt --manifest-path src/node115-raw-response-translation/Cargo.toml --check
cargo +1.95.0 clippy --offline --manifest-path src/node115-raw-response-translation/Cargo.toml --all-targets -- -D warnings
python3 research/work-items/RE-016-node115-raw-response-translation/verify.py --target /path/to/original/hl-node
```

The verifier requires the existing pyelftools and Capstone tooling. Seven debug/release tests pass:131073 consecutive signed error codes plus extremes; absent versus null;20001 signed decimal values plus boundaries;4096 full-width pairs; nonfinite values; nested data through the real continuation relation; all256 trailing bytes; failure precedence; preserved32-byte success; and explicit unsupported boundaries. These are independent Rust fixture tests plus static target checks, not runtime differential equivalence. Repository checks are recorded separately by the publisher; no hosted CI result is inferred.

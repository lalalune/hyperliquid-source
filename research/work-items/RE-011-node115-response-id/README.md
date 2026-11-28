# Response IDs on the node 115 EVM RPC reconstruction

A client of the offline HTTP service could not correlate an ordinary block-number
query when its string ID contained an escaped quote. A null ID became the number
1 and a nested extension member could be mistaken for the envelope ID. The
loopback test below failed on integration commit 2da45cb0a761cff6b478e40421699857d87a94df
and now exercises the reconstructed server over HTTP across a checkpoint restart.

## Target and field binding

The input is the Linux x86-64 node 115 ELF, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses below are ELF virtual addresses. The wave-5 Rust vendor census already
identified a 330-byte Response serializer in [its compiled object comparison](../RE-002-node115-rust-vendor-wave5-census/README.md).
The pinned public comparison is jsonrpsee-types 0.26.1, crate SHA-256
`e6e6de48c2fb8ba2773f4429c28349576f98d73a3b1d647d963f96df53210312`.
Its Id type admits a string, an unsigned 64-bit integer or null.
[Public release source](https://docs.rs/crate/jsonrpsee-types/0.26.1/source/src/params.rs)

The replay checks the exact function digest and follows the immediate field
operand. At 0x1767cea the serializer takes response+0x38. The next instructions
select the two bytes at 0x4812b1 and call 0x173e530. The neighbouring method
writes the separate seven-byte jsonrpc, six-byte result and five-byte error
keys. Inside the ID writer the zero arm picks four literal null bytes, the
number arm calls the integer formatter, and the string arm passes its pointer
and length to the same string writer used for the field name. The replay reads
the call displacements and field text directly from the retained ELF.

## Reproduce

Run from the repository root with Python 3 and Rust 1.95.0.

```sh
python3 research/work-items/RE-011-node115-response-id/replay.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml
```

The loopback integration sends valid block-number requests with an escaped string,
null, u64::MAX, and a nested extension field also named id. It additionally
checks an ID-less notification produces an empty HTTP response body. Existing
integer-ID calls and method-not-found responses remain covered. The null-ID
and missing-ID cases have different meanings in the public
[JSON-RPC 2.0 protocol](https://www.jsonrpc.org/specification#notification).

This is a field-level binding and a fix in the independently written HTTP
harness. The HTTP status chosen for a notification is local transport behavior.
The static evidence does not establish whole-transport identity, native batch
handling, or an exact version for every linked dependency. No captured code
was run. The original evidence retains its existing rights.

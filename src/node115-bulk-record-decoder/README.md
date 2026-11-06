# node115 fixed bulk record decoder

Independent MIT `no_std` Rust for the whole logical record at ELF VA
`0x5968840..0x5968980` and fixed-copy helper `0x58214b0..0x582153d`.
Target node #115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Evidence: `research/work-items/RE-005-bulk-record-decoder-115/`.

`decode_prefix(input, limit, charged)` reads two variable-width scalar values,
then exactly 2048 uninterpreted bytes. It returns an owned `[u8; 2048]`, the
two values, remaining input and final logical charge. Values' names/units and
the blob's semantic format remain unknown. No hidden header transformation is
performed: the captured helper and wrapper copy all 2048 bytes unchanged.

The existing MIT `node115-u64-reader-state` crate supplies real scalar parsing.
Its native siblings share all established value/cursor/charge operations;
this reader family's actual invalid-marker diagnostic field1 is consistently
5, projected explicitly in this crate. There is no mock dependency.

Canonical unlimited/limited modes are `None`/`Some(limit)`. Scalar charges are
8 each, then the whole blob is charged 2048, regardless of encoded scalar
width. Count overflow does not store a wrapped count; a nonoverflowing charge
commits before the limit comparison. Short blob input is not consumed, but its
charge remains. Later failures retain both scalar cursor advances.

Safe `Result`, ownership, enums and array layout do not reproduce native
Result storage, stack copies, padding, allocation or error object ABI. This is
one prefix decoder, not a sequence/container, validated application schema or
whole node. All full-scope gates and byte-coverage figures remain unchanged.

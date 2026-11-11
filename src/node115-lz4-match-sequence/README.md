# node115 LZ4 conditional match-sequence emission

Independent MIT `no_std` Rust for the whole selected emission stage in both
node #115 compressor bodies, not an invented standalone native function.
Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Evidence: `research/work-items/RE-012-lz4-match-sequence-115/`.

`emit(literals, additional_match, distance, sink, &mut used)` appends:

1. Token with saturated literal and additional-match nibbles.
2. Literal excess bytes when literal count >=15, including required zero.
3. The literal span, with one whole-span capacity check.
4. A little-endian u16 offset, with one two-byte capacity check.
5. Match excess bytes when additional match count >=15, including zero.

`additional_match` excludes the initial four bytes already matched by the
compressor caller. This stage neither searches for nor validates that match.
A supplied zero distance is emitted as zero: the local writer performs no
zero-distance check. That does not assert a valid complete compressed block.

The initialized prefix remains when any later stage fails. Literal and offset
capacity refusals do not copy partial payloads; extensions commit byte by byte.
Errors identify stages, not original panic objects or catchability. Rust
borrows enforce disjoint valid source/output spans. `used > sink.len()` is
an explicit safe-adapter rejection before mutation. Original invalid-pointer
and invalid-source-span behavior is outside this interface.

The scalar extension loop matches the logical byte/count behavior of native
grouped stores, not their instruction or asynchronous-fault granularity.
No full compressor, match selection, dictionary mutation, native ABI or binary
identity is claimed. Full-scope gates and byte coverage remain unchanged.

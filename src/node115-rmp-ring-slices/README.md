# Node #115 MessagePack sequence inputs

`sequence_input` prepares the argument to the inner collector of the 29
sequence-form `serialize_newtype_struct` bodies. The caller supplies the name,
the four observed value words, and the element stride from the chosen body.
The exact reserved name `_ExtStruct` returns the diagnostic `expected tuple`
before representation selection. A top-bit-only tag selects the tree record.
Its two cursor handles carry the same root and height, and a null root forces
the count to zero even if the supplied length is nonzero. Other tag words
supply the capacity to `ring_slices`. The ring input exposes its five defined
words, including tag 2. Iterator traversal, the inner serializer, output bytes
and allocator behavior remain outside this model.

Target evidence: `research/work-items/serialization-rmp-newtype-forward-115`,
node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The sample table includes 725 tree and 725 ring cases across all 29 sequence bodies. Tests compare the reconstructed record words with the recorded inner
arguments; they do not run or emulate the captured binary.

Run with `cargo test --manifest-path src/node115-rmp-ring-slices/Cargo.toml`.

The caller supplies `capacity`, `head`, `length`, buffer address, and element
stride from the observed value layout. Arithmetic on addresses wraps at 64 bits,
matching the recorded machine arithmetic. Preconditions such as backing buffer
validity are outside this model.

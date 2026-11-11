# Node #115 MessagePack ring-buffer slices

Models the two-slice record passed by the `serialize_newtype_struct` sequence
forwarders when their source is the ring-buffer representation. The model is
limited to address arithmetic and leaves serialization, allocation, and the
inner serializer outside its scope.

Target evidence: `research/work-items/serialization-rmp-newtype-forward-115`,
node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The sample table includes 725 ring cases across empty, contiguous, and wrapped
layouts. Tests compare the reconstructed record words with the recorded inner
arguments; they do not run or emulate the captured binary.

Run with `cargo test --manifest-path src/node115-rmp-ring-slices/Cargo.toml`.

The caller supplies `capacity`, `head`, `length`, buffer address, and element
stride from the observed value layout. Arithmetic on addresses wraps at 64 bits,
matching the recorded machine arithmetic. Preconditions such as backing buffer
validity are outside this model.

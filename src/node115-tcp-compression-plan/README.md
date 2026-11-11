# node115 TCP compression plan

MIT, independently authored Rust. A dependency-free `no_std` library for the
selected sender's eligibility, allocation arithmetic, codec selection, inner
length prefix and conditional outer framing. See
`research/work-items/RE-012-tcp-compression-plan-115/README.md` for target identity,
original bytes, the frozen mathematical oracle and actual compiled controls.

`plan(input_len, context_field)` returns either a raw five-byte header or a
`CompressionPlan`. Its private fields prevent callers from inventing an
unchecked allocation size. A compressed plan exposes the observed requested
capacities, scratch selection and four-byte little-endian original length.
`finish(tag, written)` describes the selected caller relation after the codec
and opaque helpers normally return. The observed tag-one unwrap path becomes
an explicit logical error; no panic ABI or unwind is reproduced. Success keeps
marker one even when the selected payload is larger than the input.

This is not a codec or sender. `u64` lengths make target arithmetic testable
without allocating enormous slices. They do not assert valid native slices,
successful allocations or valid arbitrary codec return values. There is no
networking or captured-code execution. The context field's type is unknown.

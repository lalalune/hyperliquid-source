# node115 eight-word / raw-trailer record

Independent MIT `no_std` + `alloc` Rust for the complete value-specific size
and byte writer at ELF VAs `0x5967f70..0x596809e` and
`0x59681d0..0x5968332`. Target node #115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Evidence: `research/work-items/RE-005-octet-record-encoder-115/`.

`Record { words: [u64; 8], trailer: u8 }` is a logical wire projection.
`count` visits each word in order, preserving a partial scalar count at an
observed overflow-helper boundary, then adds one. `write` writes eight ordered
minimal varints and one raw byte to a real vector. The trailer is not coerced
to bool. Failures preserve previous fields and any current scalar marker.

The source's pointer-containing record layout, application field names/units,
native Result/panic ABI and full parent serializer are not recovered.

`scalar/` is the exact licensed writer source snapshot from PR2809 at commit
`e685a25fae1dcd5b12fa89449e1a5c4c66c91b7e`, with MIT LICENSE, source hash and
provenance. `counter/` is a real private package adapter to the existing base
`src/node115-varint-size-state/lib.rs`, also hash-bound. Neither stubbed
dependencies nor a pending unmerged relative path are used; no original Cargo
workspace or new primitive-completion credit is claimed.

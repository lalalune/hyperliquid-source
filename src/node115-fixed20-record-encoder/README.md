# node115 fixed20-prefix / four-word record

Independent MIT `no_std` + `alloc` Rust for complete record encoder
`0x5967d90..0x5967e75` and size owner `0x5967e80..0x5967f61` in node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Evidence: `research/work-items/RE-005-fixed20-record-encoder-115/`.

`Record { prefix:[u8;20], words:[u64;4] }` expresses wire order: twenty raw
bytes, followed by four ordered minimal unsigned64 encodings. There is no
prefix length field, endian conversion or inferred address/hash meaning.

`count` commits the whole twenty-byte count before counting the words; a later
scalar overflow preserves earlier counts and that scalar's marker increment.
`write` reserves all twenty bytes before copying any prefix byte, then uses
real scalar writers on an actual vector. Allocation failure preserves the
existing prefix and preceding fields; partial scalar markers remain intact.
Safe boundary enums do not reproduce native panic/Result ABI or recoverability.

Scalar source is the exact licensed PR2809 snapshot at
`e685a25fae1dcd5b12fa89449e1a5c4c66c91b7e`, with LICENSE/hash/provenance in
`scalar/`. `counter/` is a real private adapter to unchanged existing base
Rust. No absent pending source, fake dependency or original-workspace claim is
used. These previously established primitives receive no new credit.

The actual parent selects this child under raw index2 and writes its own byte2.
That parent's tag and other variants are not part of this independent type API.

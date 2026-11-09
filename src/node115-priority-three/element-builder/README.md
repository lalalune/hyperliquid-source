# Node115 element builder

Independent `no_std` value projection of the one per-field 0xb0-byte element
construction recovered by RE-006. It sets the +0x40/+0x60 product fields to
zero, writes scale `10^14` at +0x58 and +0x78, and copies the source tail into
+0x80..+0xa0.

The original source element type, ownership, allocator, generic builders and
join/callee effects remain out of scope.

Target identity: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Target-grounded evidence: `research/work-items/RE-006-node115-element-argument/README.md`.

Bytes outside the documented projected fields are zero-filled by this safe host
representation; no native initialization or write claim is made for those bytes.

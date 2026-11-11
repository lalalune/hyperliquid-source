# Frozen Node115 book-ring append contract

Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The twin owner bodies are `0x5911890..0x5911b27` and
`0x5911b30..0x5911dc7`, 663 bytes each. Their selected append arm uses ring
capacity, head and length fields. On a nonfull ring it writes at
`(head + length) mod capacity` and increments length. A full ring invokes an
opaque grow helper before the append; the post-grow capacity and element payload
construction are separate boundaries.

The safe Rust relation provides `append_slot` for the validated nonfull ring and
`append_after_grow` for a caller-supplied post-grow capacity. It returns only the
physical slot and next length. It excludes payload layout, grow behavior,
allocation, the registration arm, key derivation and storage effects.

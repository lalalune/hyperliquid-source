# Frozen Node115 DB-hub byte-key lookup contract

Task RE-009. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All native addresses are unrebased ELF virtual addresses.

The source evidence is the complete FDE `0x1692ca0..0x1692fe9`, 841 bytes,
SHA-256
`01f207a1ef95d113cf325e6b26a93e18260f89a6d96269823b1b70f75383be75`.

The selected lookup relation is:

1. Use only the low 8 bits of the supplied query word.
2. A null root is a miss.
3. At the current node, scan keys from index 0. Stop at the first key greater
   than or equal to the query.
4. If the selected key equals the query, return the value at the same index.
5. Otherwise use child index `first_greater_or_equal`; when every key is lower,
   that index is the key count.
6. After a non-match, a zero height is a miss. Decrement the height before
   following the selected child. A null child is a miss.
7. Because the native root scan precedes the height check, height zero can
   still find a key in the root, but cannot descend.

The safe Rust model requires a well-formed node: ascending unique byte keys,
one value per key, and `keys.len() + 1` child slots. Invalid source-tree
invariants, allocation, database I/O, persistence, concurrency and the
downstream call at the matched value remain outside this contract.

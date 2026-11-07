# Frozen Node115 sorted-set read-side contract

Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The selected standalone readers are `find` at
`0x51d1a80..0x51d1afb`, 123 bytes, and `contains` at
`0x243d260..0x243d309`, 169 bytes. Both walk the validated sorted-node layout
with at most 11 strictly ascending u64 keys and `n+1` child slots.

`find_position` returns the final matched node and key index, or `None` after a
valid descending walk. `contains` is the boolean specialization. No stack record,
node+0x64 payload interpretation, removal, allocation, malformed tree or
consumer-side slab lookup is included.

# Node115 sorted-set read side

Independent `no_std` implementation of the standalone sorted-set `find` and
`contains` relation recovered from node115 `0x51d1a80` and `0x243d260`.

The logical API validates the sorted-node shape and exposes a found node/key
position or a boolean. It does not interpret the native node+0x64 pointer,
remove members, allocate, traverse malformed storage or perform downstream slab
lookups.

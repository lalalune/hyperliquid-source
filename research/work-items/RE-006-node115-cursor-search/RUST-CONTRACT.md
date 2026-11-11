# Frozen Node115 u64 cursor-search contract

Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The selected body is `0x1d65920..0x1d659af` (143 bytes, SHA-256
`4f7a495bf20876b0606bf10b74cbbce7d6b8a1ebc5b55e2be63d6f7bac1297ac`),
with the byte-identical clone `0x35bdd20..0x35bddaf`.

The safe relation accepts a valid sorted B-tree node with at most 11 u64 keys,
the remaining height, and one probe key. At each node it scans to the first key
greater than or equal to the probe:

- equal: flag `0`, current node, current height, equal-key index;
- smaller than every key: insertion position is the node count;
- remaining height zero: flag `1`, current node, height zero, insertion position;
- otherwise descend the selected child and decrement height.

The model excludes native pointer layout, allocation/ownership, malformed trees,
the downstream callbacks and any original source ABI. It returns the final node
as a borrowed logical node rather than the native pointer.

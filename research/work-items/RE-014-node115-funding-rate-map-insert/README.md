# RE-014 — Node #115 funding-rate map insertion on vacant entries

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the fresh-entry branches at `0x4dcf88c` and `0x4dcf9f1`. Existing-value replacement is covered separately in #7392.

The flat helper `0x57ee7b0` receives the insertion index, key and the value in XMM0. After its optional growth call, it compares the suffix count `length - index` against the prefix count `index`. When the suffix is at least as large, it first decrements the head modulo capacity. Otherwise it keeps the head. Both sides call the relocation helper `0x5814d30` with different ranges. The helper then increments length and writes the key at byte +0 and the value at byte +8 of the 16-byte insertion row computed from the resulting head and index.

The tree helper `0x51ee690` allocates a 0xc0-byte node for the selected empty-root case and initializes the node header and count. It installs the node as root and clears the height. The first key goes at +0x08 and the first value at +0x60. It increments both the node's 16-bit count at +0xba and the map length at +0x10. The helper fills a four-word result with node pointer, zero, node index and the pointer to the root descriptor. The outer map operation uses the normal insertion continuation that clears EAX, distinct from the replacement return tag 1.

Movement-helper internals, allocator failure, nonempty-tree insertion and full-ring growth are outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-014-node115-funding-rate-map-insert/verify.py` from the repository root. It verifies static instructions and synthetic insertion coordinates.

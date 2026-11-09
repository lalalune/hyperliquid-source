# Node #115 raw hexadecimal decoder

This independently authored Rust value model covers the string-derived byte-slice decoder at VA `0x167afd0` in target #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Its evidence is in `research/work-items/RE-011-evm-raw-forward-115`: the complete selected decoder FDE is `[0x167afd0, 0x167b261)` (657 bytes, body SHA-256 `4f6edb464567bf90e3ba5e2f9ac743c416b7aa1828938a5036f4e61ce2543f1d`), odd-length check at `0x167afe4`, and binary lookup table at `0x46d50c`.

The API receives an already-extracted string slice. It models odd-length validation before prefix removal, lowercase-only `0x`, the observed ASCII hex alphabet, first-invalid-byte ordering, and the post-prefix invalid index. Tests consume the packet's all-256-byte table and frozen decoder cases directly.

This is not a JSON parser or a claim about arbitrary JSON escapes, native result/ABI layout, allocation or error-string behavior, raw transaction validity, or request submission. Source types and the complete Ethereum RPC pipeline remain unknown. Neither the target nor its instructions are run or emulated.

# RE-014 — Node #115 funding-rate caller result routing

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The [funding-rate packet](../RE-014-funding-rate-value-115/) identifies the callee `0x44d8590` and slot `0x64e7898`. Its callers in `0x54a9c70` and `0x54b66b0` form the asset key as `10000 * [r15+0x50] + r13`, with separate overflow branches for the multiply and add. They call the same relocated slot with the key in RSI.

If RAX is 1, the caller retains the XMM0 value and goes directly to the common collection call `0x4dcf640`, sending the asset key and retained value. Other tags produce +0.0 for the same call. Those tags also lead to a separate key list when the key is below 10000 and absent from the tree rooted at +0x4c8. On that path the caller appends the key to an eight-byte-element buffer and increments the length before the common collection call. A tree hit, or a key of 10000 or greater, skips the separate append.

This packet binds the selected caller paths and arguments. Collection callee internals and later consumers of the separate key list remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-014-node115-funding-rate-callers/verify.py` from the repository root. The verifier checks pinned static windows, relative edges, the ELF relocation and synthetic routing tuples.

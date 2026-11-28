# RE-004 — Node #115 prepared quantity formatter handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [quantity preparation packet](../RE-004-node115-quantity-preparation-rust/) identifies slot `0x64e95c8` but leaves its formatter body outside scope.

The formatter `0x5c449c0` reads the flag at bit 28 of the context dword at +0x10 and the 16-bit field at +0x16. It passes both to `0x5c43040`, along with the quantity input and a zero argument. It copies the resulting scratch bytes to local storage and branches on whether the helper's dword at result +0x28 is 1.

For the tag-1 path it constructs a temporary from a one-byte literal `0` and the helper's +0x30 word. It then calls `0x5c45d60` with a pair of pointer/length components. The resulting pointer and length go to the common sink. The other path sends the local byte span at stack +0x54 and its length directly. Both call the relocated slot `0x64dfa00 -> 0x167e9d0`, passing the inverted high bit of the original quantity's first dword as a separate flag and the same mode arguments. The tag-1 path conditionally frees both temporary buffers and preserves the sink's return status.

This establishes the selected handoff, format selection and cleanup sequence. The formatter helper's digit-generation rules, sink internals and byte-for-byte wire output remain open. Run `PYTHONPATH=tools python3 research/work-items/RE-004-node115-quantity-formatter-handoff/verify.py` from the repository root.

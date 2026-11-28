# RE-010 — Node #115 ENV79 standard fixstr map value

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows a standard MessagePack fixstr value through the value call identified in #7446.

The value decoder `0x14b1f30` extracts the low five bits of the fixstr marker as the payload byte count. On the selected valid string path, it advances the cursor by that count, updates the remaining count, and supplies the span to the validation slot and the owned-string constructor at `0x152fbd0`.

When the constructor succeeds for a nonempty valid string, it copies the payload into an allocation of the same length. It sets result tag 9, then returns capacity, data pointer and length in the three words at +8, +0x10 and +0x18. Both size words equal the payload byte count. On the zero-length success path, the constructor sets the pointer word to 1 and leaves both size words zero. The caller transfers the three output words together and sets tag 9 before returning to the map decoder.

This establishes the ordinary string representation the map can consume. Other marker forms, validation diagnostics and the schema's field name remain open. Run `PYTHONPATH=tools python3 research/work-items/RE-010-node115-env79-fixstr-value/verify.py` at the repository root.

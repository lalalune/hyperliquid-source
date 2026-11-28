# RE-009 — Node #115 quantity tree replacement

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. In the tree arm of quantity upsert `0x4dd6150`, the equal-key branch at `0x4dd64e3` addresses a 16-byte value slot.

The path copies the previous 16 bytes to the result at offset +4, then copies the incoming 16 bytes into the same tree slot. It sets the result tag to one and returns. A nonmatching comparison instead continues through a child or prepares the vacant-entry insertion at `0x51f21d0`, covered in #7663. The evidence here isolates replacement for an existing key. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-replacement/verify.py`.

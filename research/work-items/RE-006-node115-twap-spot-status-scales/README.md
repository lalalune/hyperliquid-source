# RE-006 — Node #115 spot TWAP finish status scale fields

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [finish handoff packet](../RE-006-twap-finish-115/) identifies this spot builder at `0x5182640`. #7341 covers a different perpetual builder.

The spot builder's selected amount paths use the first token ID at +0 of a two-word token reference. A nonzero amount checks that ID against the metadata count, gets the decimal byte at +0x48 of the corresponding 0x158-byte token record and divides the unsigned amount by the binary64 power of ten at that index. The zero-amount branches preserve zero without indexing metadata. The two independently read amounts reach output +0x38 and +0x40.

A third nonzero path reads both token IDs. It subtracts the first token's +0x48 decimal byte from the second token's +0x49 byte, with a distinct underflow edge. The selected result divides the unsigned input from RBP by the corresponding table entry, writes presence tag 1 at output +0, and stores the quotient at +8. This two-token scale derivation distinguishes it from the same-token amount fields and from the previously documented perpetual builder.

Other inputs, panic behavior, and the full finish status schema remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-006-node115-twap-spot-status-scales/verify.py` from the repository root.
